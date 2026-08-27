/**
 * Decides which decrypted chat attachments are rendered inline in the message
 * bubble instead of being handed to the OS as a download.
 *
 * Kept out of the page component so the rules are testable on their own: the
 * fallbacks below are where the real ambiguity lives, and getting them wrong is
 * either a photo that will not show or content rendered that should not be.
 */

export type InlineMediaKind = "image" | "video" | "audio";

/** Only the attachment fields the decision actually depends on. */
export interface InlineMediaCandidate {
  kind: "file" | "voice";
  name: string;
  content_type: string;
}

/**
 * Extensions consulted ONLY when the declared content type is absent or generic.
 * Senders legitimately ship photos as application/octet-stream, so a strict
 * content-type check alone would leave real images stuck as opaque downloads.
 */
const inlineImageExtensions = new Set(["png", "jpg", "jpeg", "gif", "webp", "bmp", "avif", "heic", "heif"]);
const inlineVideoExtensions = new Set(["mp4", "webm", "mov", "m4v", "ogv"]);
const inlineAudioExtensions = new Set(["mp3", "wav", "ogg", "oga", "m4a", "aac", "flac", "opus", "weba"]);

function fileExtension(name: string): string {
  const dot = name.lastIndexOf(".");
  return dot === -1 ? "" : name.slice(dot + 1).toLowerCase();
}

/**
 * Returns the element to render this attachment with, or null to keep the
 * download path.
 *
 * SVG is deliberately excluded. To a person it reads as "an image", but to the
 * renderer it is a document with its own fetching and scripting surface, and this
 * is attacker-supplied content arriving over a chat from a party the recipient
 * may not trust. It downloads instead, where the OS decides what opens it.
 */
export function inlineMediaKind(attachment: InlineMediaCandidate): InlineMediaKind | null {
  // A voice note is audio regardless of how the recorder labelled the container.
  if (attachment.kind === "voice") return "audio";

  const declared = (attachment.content_type || "").toLowerCase().split(";")[0]!.trim();
  const extension = fileExtension(attachment.name);

  if (declared === "image/svg+xml" || extension === "svg" || extension === "svgz") return null;

  if (declared.startsWith("image/")) return "image";
  if (declared.startsWith("video/")) return "video";
  if (declared.startsWith("audio/")) return "audio";

  if (!declared || declared === "application/octet-stream") {
    if (inlineImageExtensions.has(extension)) return "image";
    if (inlineVideoExtensions.has(extension)) return "video";
    if (inlineAudioExtensions.has(extension)) return "audio";
  }

  return null;
}
