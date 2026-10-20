#!/usr/bin/env node
/**
 * Secure Chat account-state reset.
 *
 * Purges the messaging domain (devices, key material, conversations, envelopes,
 * attachments, telemetry) so an account can re-register from a clean slate,
 * while PRESERVING the things that are not chat state and must survive:
 *
 *   * auth.users            — the login itself. Deleting it cascades into
 *                             profiles AND billing_subscriptions, i.e. it
 *                             destroys the account's paid plan. Never touched.
 *   * profiles              — username, avatar, tier.
 *   * billing_subscriptions — the plan that migration 030's RESTRICTIVE RLS
 *                             checks before it will accept a single envelope
 *                             INSERT. Wipe this and the account cannot send
 *                             even after a perfect reset.
 *   * messaging_user_settings / messaging_user_modules — UI preferences and
 *                             module enablement, not crypto state.
 *   * messaging_call_relay  — deployment-wide TURN/STUN config, not per-user.
 *   * vault-encrypted storage — the Quantum Vault is a separate feature whose
 *                             VMK is password-wrapped, so its files may still
 *                             be recoverable. Opt in with --include-vault.
 *
 * Usage:
 *   node tools/messaging-reset.mjs                      # read-only report
 *   node tools/messaging-reset.mjs --reset --confirm "RESET SECURE CHAT DATA"
 *   node tools/messaging-reset.mjs --reset --confirm "..." --users a@x.com,b@y.com
 *   node tools/messaging-reset.mjs --reset --confirm "..." --include-vault
 */
import { createClient } from "@supabase/supabase-js";
import fs from "node:fs";

const CONFIRM_PHRASE = "RESET SECURE CHAT DATA";

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(`--${name}`);
const value = (name) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : null;
};

const doReset = flag("reset");
const includeVault = flag("include-vault");
const confirm = value("confirm");
const userFilter = (value("users") ?? "")
  .split(",")
  .map((entry) => entry.trim().toLowerCase())
  .filter(Boolean);

function loadEnv() {
  const path = new URL("../.env.local", import.meta.url);
  if (!fs.existsSync(path)) {
    throw new Error("qguard-messaging/.env.local not found — SUPABASE_SERVICE_ROLE_KEY is required.");
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
  if (!env.VITE_SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error("VITE_SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must both be set in .env.local");
  }
  return env;
}

const env = loadEnv();
const sb = createClient(env.VITE_SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
});

/**
 * Purge order is child-to-parent. Most of these FKs are ON DELETE CASCADE, so
 * deleting conversations alone would take the envelopes with them — but an
 * explicit ordered pass reports a real per-table count instead of hiding the
 * work inside a cascade, which is what makes the post-run verification
 * meaningful.
 *
 * `users` lists every column that scopes a row to an account. A row is deleted
 * when ANY of them matches the selected set, so a two-party artefact (an
 * envelope, a contact edge) goes when either side is reset.
 * `notNull` is a column with a NOT NULL guarantee, used to build the
 * "match everything" filter PostgREST requires on a DELETE.
 * `optional` marks a table from a migration that may not be applied to the
 * project yet (036+): absent, it is reported and skipped, never "0 rows".
 */
const TABLES = [
  { name: "messaging_channel_posts", users: ["sender_user_id"], notNull: "id", optional: true },
  { name: "messaging_channel_invites", users: ["created_by"], notNull: "id", optional: true },
  { name: "messaging_conversation_owner_history", users: ["owner_user_id"], notNull: "conversation_id", optional: true },
  { name: "messaging_recovery_releases", users: ["owner_user_id", "guardian_user_id"], notNull: "id", optional: true },
  { name: "messaging_recovery_shares", users: ["owner_user_id", "guardian_user_id"], notNull: "id", optional: true },
  { name: "messaging_recovery_requests", users: ["user_id"], notNull: "request_id", optional: true },
  { name: "messaging_social_recovery", users: ["user_id"], notNull: "user_id", optional: true },
  { name: "messaging_directory_search_log", users: ["user_id"], notNull: "user_id", optional: true },
  { name: "messaging_message_user_states", users: ["user_id"], notNull: "user_id" },
  { name: "messaging_delivery_receipts", users: ["recipient_user_id"], notNull: "id" },
  { name: "messaging_message_envelopes", users: ["sender_user_id", "recipient_user_id"], notNull: "id" },
  { name: "messaging_typing_indicators", users: ["user_id"], notNull: "user_id" },
  { name: "messaging_conversation_user_states", users: ["user_id"], notNull: "user_id" },
  { name: "messaging_conversation_members", users: ["user_id"], notNull: "conversation_id" },
  { name: "messaging_conversations", users: ["owner_user_id"], notNull: "id" },
  { name: "messaging_call_signals", users: ["from_user_id", "to_user_id"], notNull: "id" },
  { name: "messaging_file_grants", users: ["recipient_user_id"], notNull: "id" },
  { name: "messaging_device_verification_payloads", users: ["user_id"], notNull: "id" },
  { name: "messaging_device_link_requests", users: ["user_id"], notNull: "id" },
  { name: "messaging_one_time_prekeys", users: ["user_id"], notNull: "id" },
  { name: "messaging_signed_prekeys", users: ["user_id"], notNull: "id" },
  { name: "messaging_devices", users: ["user_id"], notNull: "id" },
  { name: "messaging_account_recovery", users: ["user_id"], notNull: "user_id" },
  { name: "messaging_contacts", users: ["owner_user_id", "contact_user_id"], notNull: "id" },
  { name: "messaging_security_events", users: ["user_id"], notNull: "id" },
  { name: "messaging_crypto_telemetry", users: ["user_id"], notNull: "id" },
];

const VAULT_TABLES = [{ name: "messaging_vault_files", users: ["owner_user_id"], notNull: "id" }];

const PRESERVED = [
  ["auth.users", "the login — deleting it cascades into profiles AND billing_subscriptions"],
  ["profiles", "username, avatar, tier"],
  ["billing_subscriptions", "the paid plan the envelope-INSERT RLS policy checks"],
  ["messaging_user_settings", "UI preferences"],
  ["messaging_user_modules", "module enablement"],
  ["messaging_call_relay", "deployment-wide TURN/STUN config"],
  ["messaging_app_roles", "operator role grants (account configuration)"],
];

// PostgREST "table not in the schema cache" / Postgres "relation does not exist".
function isMissingTable(error) {
  return error?.code === "PGRST205" || error?.code === "42P01";
}

async function countRows(table, ids) {
  const spec = [...TABLES, ...VAULT_TABLES].find((t) => t.name === table.name) ?? table;
  let query = sb.from(spec.name).select("*", { count: "exact", head: true });
  query = applyScope(query, spec, ids);
  const { count, error } = await query;
  if (error && spec.optional && isMissingTable(error)) return { count: 0, error: null, absent: true };
  // A failed count must never render as 0 — that would report a purge as
  // complete when the table was simply unreadable.
  if (error) return { count: null, error: error.message };
  return { count, error: null };
}

const ABSENT = "not on this project (migration not applied) - skipped";

function applyScope(query, spec, ids) {
  if (!ids) return query.not(spec.notNull, "is", null);
  const clause = spec.users.map((col) => `${col}.in.(${ids.join(",")})`).join(",");
  return query.or(clause);
}

async function resolveUsers() {
  const { data, error } = await sb.auth.admin.listUsers({ perPage: 1000 });
  if (error) throw new Error(`listUsers failed: ${error.message}`);
  const users = data.users.map((u) => ({ id: u.id, email: u.email ?? "(no email)", created_at: u.created_at, last_sign_in_at: u.last_sign_in_at }));
  if (userFilter.length === 0) return { users, ids: null };
  const selected = users.filter((u) => userFilter.includes(u.email.toLowerCase()) || userFilter.includes(u.id));
  const missing = userFilter.filter(
    (entry) => !users.some((u) => u.email.toLowerCase() === entry || u.id === entry),
  );
  if (missing.length > 0) throw new Error(`--users did not match any account: ${missing.join(", ")}`);
  return { users: selected, ids: selected.map((u) => u.id) };
}

async function listStorageFiles(bucket, prefix = "") {
  const { data, error } = await sb.storage.from(bucket).list(prefix, { limit: 1000 });
  // A folder that could not be listed must never read as an empty one: the
  // purge would skip its objects and still report the bucket as handled.
  if (error) throw new Error(`storage:${bucket} could not list "${prefix || "/"}": ${error.message}`);
  const files = [];
  for (const entry of data) {
    const path = prefix ? `${prefix}/${entry.name}` : entry.name;
    // Supabase marks real objects with an id; folders come back without one.
    if (entry.id) files.push(path);
    else files.push(...(await listStorageFiles(bucket, path)));
  }
  return files;
}

async function storageTargets(ids) {
  const buckets = [{ bucket: "messaging-files", label: "chat attachments" }];
  if (includeVault) buckets.push({ bucket: "vault-encrypted", label: "Quantum Vault files" });
  const targets = [];
  for (const { bucket, label } of buckets) {
    let files = await listStorageFiles(bucket);
    if (ids) files = files.filter((path) => ids.some((id) => path.includes(id)));
    targets.push({ bucket, label, files });
  }
  return targets;
}

function heading(text) {
  console.log(`\n${text}\n${"-".repeat(text.length)}`);
}

async function main() {
  const { users, ids } = await resolveUsers();
  const tables = includeVault ? [...TABLES, ...VAULT_TABLES] : TABLES;

  console.log(`project : ${env.VITE_SUPABASE_URL}`);
  console.log(`mode    : ${doReset ? "RESET (destructive)" : "report (read-only)"}`);
  console.log(`scope   : ${ids ? `${users.length} selected account(s)` : `ALL accounts (${users.length})`}`);
  console.log(`vault   : ${includeVault ? "INCLUDED" : "preserved (pass --include-vault to purge)"}`);

  heading("Accounts in scope");
  for (const u of users) {
    console.log(` ${u.id}  ${u.email.padEnd(32)} created=${u.created_at?.slice(0, 10)} lastSignIn=${u.last_sign_in_at?.slice(0, 10) ?? "-"}`);
  }

  heading("Chat state to purge");
  const absent = new Set();
  for (const table of tables) {
    const { count, error, absent: isAbsent } = await countRows(table, ids);
    if (isAbsent) absent.add(table.name);
    console.log(` ${table.name.padEnd(42)} ${isAbsent ? ABSENT : error ? `UNREADABLE (${error})` : count}`);
  }

  const storage = await storageTargets(ids);
  for (const target of storage) {
    console.log(` ${`storage:${target.bucket}`.padEnd(42)} ${target.files.length} object(s) — ${target.label}`);
  }

  heading("Preserved (not touched)");
  for (const [name, why] of PRESERVED) console.log(` ${name.padEnd(26)} ${why}`);

  if (!doReset) {
    console.log(`\nRead-only report. To execute:\n  node tools/messaging-reset.mjs --reset --confirm "${CONFIRM_PHRASE}"`);
    return;
  }

  if (confirm !== CONFIRM_PHRASE) {
    console.error(`\nRefusing to reset: --confirm must be exactly "${CONFIRM_PHRASE}".`);
    process.exitCode = 1;
    return;
  }

  heading("Purging");
  let failed = false;
  for (const table of tables) {
    if (absent.has(table.name)) {
      console.log(` ${table.name.padEnd(42)} ${ABSENT}`);
      continue;
    }
    let query = sb.from(table.name).delete({ count: "exact" });
    query = applyScope(query, table, ids);
    const { count, error } = await query;
    if (error) {
      failed = true;
      console.log(` ${table.name.padEnd(42)} FAILED: ${error.message}`);
    } else {
      console.log(` ${table.name.padEnd(42)} deleted ${count ?? 0}`);
    }
  }

  for (const target of storage) {
    if (target.files.length === 0) {
      console.log(` ${`storage:${target.bucket}`.padEnd(42)} nothing to delete`);
      continue;
    }
    const { error } = await sb.storage.from(target.bucket).remove(target.files);
    if (error) {
      failed = true;
      console.log(` ${`storage:${target.bucket}`.padEnd(42)} FAILED: ${error.message}`);
    } else {
      console.log(` ${`storage:${target.bucket}`.padEnd(42)} deleted ${target.files.length}`);
    }
  }

  // Verification is the point of the exercise: a delete that silently matched
  // nothing looks identical to a successful one in the output above.
  heading("Verification (rows remaining)");
  let residual = 0;
  for (const table of tables) {
    const { count, error, absent: isAbsent } = await countRows(table, ids);
    if (isAbsent) {
      console.log(` ${table.name.padEnd(42)} ${ABSENT}`);
      continue;
    }
    if (error) {
      failed = true;
      console.log(` ${table.name.padEnd(42)} UNREADABLE (${error})`);
      continue;
    }
    residual += count;
    console.log(` ${table.name.padEnd(42)} ${count}${count === 0 ? "" : "  <-- NOT EMPTY"}`);
  }
  for (const target of storage) {
    let files = await listStorageFiles(target.bucket);
    if (ids) files = files.filter((path) => ids.some((id) => path.includes(id)));
    residual += files.length;
    console.log(` ${`storage:${target.bucket}`.padEnd(42)} ${files.length}${files.length === 0 ? "" : "  <-- NOT EMPTY"}`);
  }

  heading("Preserved (verified intact)");
  for (const name of ["profiles", "billing_subscriptions", "messaging_user_settings", "messaging_user_modules"]) {
    const { count, error } = await sb.from(name).select("*", { count: "exact", head: true });
    console.log(` ${name.padEnd(26)} ${error ? `UNREADABLE (${error.message})` : `${count} row(s)`}`);
  }
  const { data: after } = await sb.auth.admin.listUsers({ perPage: 1000 });
  console.log(` ${"auth.users".padEnd(26)} ${after?.users.length ?? "?"} account(s)`);

  if (failed || residual > 0) {
    console.error("\nReset did NOT fully complete — see the FAILED / NOT EMPTY lines above.");
    process.exitCode = 1;
    return;
  }

  console.log(`
Reset complete. Every account keeps its login, profile and plan.

Next, on EACH physical device (the server no longer has their keys, but the
devices still hold the old local identity):
  Android : Settings > Apps > QGuard > Storage > Clear storage, then sign in.
  Desktop : sign out, then use Device Trust Center > Reset Device Keys.
This makes the device mint a fresh identity and register it against the clean
server state. Skipping it leaves a device publishing an identity whose prekeys
were just deleted.`);
}

main().catch((error) => {
  console.error(`\n${error.message}`);
  process.exitCode = 1;
});
