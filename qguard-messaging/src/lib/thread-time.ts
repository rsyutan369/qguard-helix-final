/**
 * The short time a conversation row shows, messenger-style: the clock time
 * today, "Yesterday", the weekday within the last week, then the date (with
 * the year only when it is not this year). Empty when the time is unknown --
 * a row must never show a made-up time.
 */
export function formatThreadTime(iso: string | null | undefined, now: Date = new Date()): string {
  if (!iso) return "";
  const time = new Date(iso);
  if (Number.isNaN(time.getTime())) return "";

  const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const dayMs = 24 * 60 * 60 * 1000;
  const at = time.getTime();

  if (at >= startOfToday) return time.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
  if (at >= startOfToday - dayMs) return "Yesterday";
  if (at >= startOfToday - 6 * dayMs) return time.toLocaleDateString(undefined, { weekday: "short" });
  if (time.getFullYear() === now.getFullYear()) return time.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  return time.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}
