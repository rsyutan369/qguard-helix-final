#!/usr/bin/env node
/**
 * Regression check for the defect fixed by migration 033.
 *
 * A device re-key used to leave an account holding zero active
 * messaging_conversation_members rows for threads it demonstrably belongs to.
 * Because the envelope INSERT policy gates on
 * `is_messaging_conversation_member(conversation_id, <user>)`, that account
 * could sign in, register keys and open the thread, but every send was rejected
 * with `42501 new row violates row-level security policy` and surfaced only as
 * "Encryption failed" -- a state nothing in the app could repair.
 *
 * This asserts the two things that must hold:
 *   1. migration 033 is applied (the reinstate RPC exists);
 *   2. no account is STRANDED -- party to a conversation's envelopes, or its
 *      owner, while holding no active membership row in it.
 *
 *   node tools/messaging-membership-check.mjs
 *
 * Exits non-zero when either fails.
 */
import { createClient } from "@supabase/supabase-js";
import fs from "node:fs";

const path = new URL("../.env.local", import.meta.url);
if (!fs.existsSync(path)) {
  console.error("qguard-messaging/.env.local not found — SUPABASE_SERVICE_ROLE_KEY is required.");
  process.exit(1);
}
const env = Object.fromEntries(
  fs.readFileSync(path, "utf8")
    .split(/\r?\n/)
    .filter((line) => line.includes("=") && !line.trim().startsWith("#"))
    .map((line) => {
      const i = line.indexOf("=");
      return [line.slice(0, i).trim(), line.slice(i + 1).trim()];
    }),
);

const sb = createClient(env.VITE_SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
});

// A query that errors must never be read as "no rows" — that is exactly how a
// stranded account would be reported as healthy.
async function rows(table, columns) {
  const { data, error } = await sb.from(table).select(columns).limit(5000);
  if (error) throw new Error(`${table}: ${error.message}`);
  return data ?? [];
}

let failures = 0;

console.log(`project: ${env.VITE_SUPABASE_URL}\n`);

// 1. Is migration 033 applied?
//
// This probe runs on the service role, which has no auth.uid(), so the function
// is EXPECTED to raise `authentication required` -- that response proves it is
// both present and correctly refusing an unauthenticated caller. Only
// PGRST202 ("could not find the function") means the migration is missing.
const probe = await sb.rpc("reinstate_messaging_conversation_membership", {
  p_device_id: "00000000-0000-0000-0000-000000000000",
});
// `42501 permission denied for function` is the same proof from one layer up:
// EXECUTE is granted to signed-in users only, so the service role is turned
// away before the body runs. A function that did not exist could not deny it.
const guardTripped = /authentication required/i.test(probe.error?.message ?? "")
  || (probe.error?.code === "42501" && /permission denied for function/i.test(probe.error.message ?? ""));
if (probe.error?.code === "PGRST202") {
  failures += 1;
  console.log("FAIL  migration 033 is NOT applied — reinstate_messaging_conversation_membership() is missing.");
  console.log("      Devices that re-key will silently lose conversation membership and be unable to send.");
  console.log("      Apply supabase/migrations/033_membership_survives_device_rekey.sql.");
} else if (probe.error && !guardTripped) {
  failures += 1;
  console.log(`FAIL  reinstate_messaging_conversation_membership() errored: ${probe.error.message}`);
} else {
  console.log(`PASS  migration 033 applied — membership is reinstated on device registration${guardTripped ? " (auth guard verified)" : ""}.`);
}

// 2. Is any account stranded?
const [convs, members, envelopes] = await Promise.all([
  rows("messaging_conversations", "id,owner_user_id,conversation_type"),
  rows("messaging_conversation_members", "conversation_id,user_id,revoked_at"),
  rows("messaging_message_envelopes", "conversation_id,sender_user_id,recipient_user_id"),
]);

const active = new Set(
  members.filter((m) => !m.revoked_at).map((m) => `${m.conversation_id}:${m.user_id}`),
);

// Everyone with a demonstrable claim to each conversation.
const parties = new Map();
const claim = (conversationId, userId) => {
  if (!conversationId || !userId) return;
  if (!parties.has(conversationId)) parties.set(conversationId, new Set());
  parties.get(conversationId).add(userId);
};
for (const c of convs) claim(c.id, c.owner_user_id);
for (const e of envelopes) {
  claim(e.conversation_id, e.sender_user_id);
  claim(e.conversation_id, e.recipient_user_id);
}

const stranded = [];
for (const [conversationId, users] of parties) {
  for (const userId of users) {
    if (!active.has(`${conversationId}:${userId}`)) stranded.push({ conversationId, userId });
  }
}

if (stranded.length === 0) {
  console.log(`PASS  no stranded account — every party to a conversation holds an active membership row (${convs.length} conversation(s) checked).`);
} else {
  failures += 1;
  console.log(`FAIL  ${stranded.length} account/conversation pair(s) stranded — these accounts cannot send (RLS 42501):`);
  const { data: userList } = await sb.auth.admin.listUsers({ perPage: 1000 });
  const email = Object.fromEntries((userList?.users ?? []).map((u) => [u.id, u.email ?? u.id]));
  for (const s of stranded.slice(0, 25)) {
    console.log(`        conversation ${s.conversationId.slice(0, 8)}  ${email[s.userId] ?? s.userId}`);
  }
  if (stranded.length > 25) console.log(`        ... and ${stranded.length - 25} more`);
  console.log("      Each account heals itself on next app launch once 033 is applied (registration rebinds membership).");
}

process.exit(failures === 0 ? 0 : 1);
