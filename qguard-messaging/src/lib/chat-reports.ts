// "Report" a contact or conversation (migration 050, messaging_submit_report).
//
// Messages are end-to-end encrypted, so a report sends only who, which
// conversation, a reason and the reporter's own words — never message content.

import { supabase } from "@/lib/supabase";

export type ReportReason = "spam" | "harassment" | "scam" | "impersonation" | "inappropriate" | "other";

export const REPORT_REASONS: Array<{ id: ReportReason; label: string; detail: string }> = [
  { id: "spam", label: "Spam", detail: "Unwanted messages, ads or repeated contact" },
  { id: "harassment", label: "Harassment or bullying", detail: "Threats, insults or targeted abuse" },
  { id: "scam", label: "Scam or fraud", detail: "Asking for money, codes, passwords or personal details" },
  { id: "impersonation", label: "Pretending to be someone else", detail: "A fake account of a person or organisation" },
  { id: "inappropriate", label: "Inappropriate content", detail: "Explicit, violent or hateful content" },
  { id: "other", label: "Something else", detail: "Describe it below" },
];

const MESSAGES: Record<string, string> = {
  QG_REPORT_RATE_LIMITED: "You have sent many reports today. Please try again tomorrow.",
  QG_REPORT_UNKNOWN_USER: "You can only report someone you have a contact or conversation with.",
  QG_REPORT_NOT_MEMBER: "You are no longer in this conversation, so it cannot be reported from here.",
  QG_REPORT_SELF: "You cannot report yourself.",
  QG_REPORT_TARGET_REQUIRED: "Nothing to report was selected.",
  QG_NOT_AUTHENTICATED: "Sign in again to send a report.",
};

export function describeReportError(error: unknown): string {
  const raw = error && typeof error === "object" && "message" in error ? String((error as { message: unknown }).message) : String(error ?? "");
  const code = Object.keys(MESSAGES).find((key) => raw.includes(key));
  if (code) return MESSAGES[code];
  if (/messaging_submit_report|does not exist|PGRST202/i.test(raw)) return "Reporting is not available on the server yet.";
  return raw || "The report could not be sent.";
}

export async function submitReport(input: {
  reportedUserId: string | null;
  conversationId: string | null;
  reason: ReportReason;
  details: string;
  alsoBlocked: boolean;
}): Promise<string> {
  const { data, error } = await supabase.rpc("messaging_submit_report", {
    p_reported_user_id: input.reportedUserId,
    p_conversation_id: input.conversationId,
    p_reason: input.reason,
    p_details: input.details.trim() || null,
    p_also_blocked: input.alsoBlocked,
  });
  if (error) throw error;
  return String(data);
}
