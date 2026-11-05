// "Share contact": a contact card is an ordinary end-to-end encrypted text
// message, so it needs no new message kind and a build without card support
// still shows it as readable text. The line `qguard-user:<id>` is the same ID
// format as the "Copy my ID" / QR code, which search already accepts.

const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const CARD_PATTERN = new RegExp(`^Contact card · (.+?)(?: \\(@([A-Za-z0-9_.-]+)\\))?\\r?\\nqguard-user:(${UUID})\\s*$`, "i");

export interface ContactCard {
  userId: string;
  name: string;
  username: string | null;
}

export function formatContactCard(card: ContactCard): string {
  const name = card.name.replace(/[\r\n]+/g, " ").trim() || "QGuard user";
  return `Contact card · ${name}${card.username ? ` (@${card.username.replace(/^@/, "")})` : ""}\nqguard-user:${card.userId.toLowerCase()}`;
}

/** The card in a message, or null when the message is not exactly a card. */
export function parseContactCard(text: string | null | undefined): ContactCard | null {
  if (!text) return null;
  const match = text.trim().match(CARD_PATTERN);
  if (!match) return null;
  return { name: match[1].trim(), username: match[2] ?? null, userId: match[3].toLowerCase() };
}
