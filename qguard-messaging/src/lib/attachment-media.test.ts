import { describe, expect, it } from "vitest";
import { inlineMediaKind, type InlineMediaCandidate } from "@/lib/attachment-media";

function file(name: string, content_type: string): InlineMediaCandidate {
  return { kind: "file", name, content_type };
}

describe("inlineMediaKind", () => {
  it("renders images and video declared by content type", () => {
    expect(inlineMediaKind(file("holiday.jpg", "image/jpeg"))).toBe("image");
    expect(inlineMediaKind(file("shot.PNG", "image/png"))).toBe("image");
    expect(inlineMediaKind(file("clip.mp4", "video/mp4"))).toBe("video");
    expect(inlineMediaKind(file("song.m4a", "audio/mp4"))).toBe("audio");
  });

  it("ignores content-type parameters and casing", () => {
    expect(inlineMediaKind(file("a.webm", "VIDEO/WEBM; codecs=vp9"))).toBe("video");
    expect(inlineMediaKind(file("a.jpg", "Image/JPEG "))).toBe("image");
  });

  it("falls back to the extension when the type is missing or generic", () => {
    // Senders really do ship photos as octet-stream; without this they would
    // stay opaque downloads and never appear in the conversation.
    expect(inlineMediaKind(file("photo.heic", "application/octet-stream"))).toBe("image");
    expect(inlineMediaKind(file("movie.mov", ""))).toBe("video");
    expect(inlineMediaKind(file("note.opus", "application/octet-stream"))).toBe("audio");
  });

  it("does not let an extension override a specific declared type", () => {
    // A real PDF named .jpg must not be rendered as an image.
    expect(inlineMediaKind(file("invoice.jpg", "application/pdf"))).toBeNull();
  });

  it("never renders SVG inline, however it is labelled", () => {
    expect(inlineMediaKind(file("logo.svg", "image/svg+xml"))).toBeNull();
    expect(inlineMediaKind(file("logo.svg", "application/octet-stream"))).toBeNull();
    expect(inlineMediaKind(file("logo.svgz", ""))).toBeNull();
    // The dangerous case: SVG content mislabelled as a safe raster type.
    expect(inlineMediaKind(file("payload.svg", "image/png"))).toBeNull();
  });

  it("treats a voice note as audio whatever the container says", () => {
    expect(inlineMediaKind({ kind: "voice", name: "note", content_type: "" })).toBe("audio");
    expect(inlineMediaKind({ kind: "voice", name: "n", content_type: "application/octet-stream" })).toBe("audio");
  });

  it("keeps ordinary documents on the download path", () => {
    expect(inlineMediaKind(file("report.pdf", "application/pdf"))).toBeNull();
    expect(inlineMediaKind(file("archive.zip", "application/zip"))).toBeNull();
    expect(inlineMediaKind(file("notes.txt", "text/plain"))).toBeNull();
    expect(inlineMediaKind(file("noextension", "application/octet-stream"))).toBeNull();
    expect(inlineMediaKind(file("script.exe", ""))).toBeNull();
  });
});
