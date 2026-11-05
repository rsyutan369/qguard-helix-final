import { Archive, File as FileIcon, FileText, Film, Folder, Image as ImageIcon, Music } from "lucide-react";
import { useEffect, useState } from "react";
import { canPreview, vaultStore, type StoreEntry } from "@/lib/vault-store";

// ---------------------------------------------------------------------------
// Entry icons and encrypted thumbnails.
//
// A thumbnail is made on this device: the core decrypts the photo / video into
// memory (fully authenticated), it is drawn small on a canvas here, and the
// JPEG goes straight back to the core, which seals it under its own key before
// it touches the disk. Nothing is cached in plaintext anywhere; the object URL
// shown lives only while the tile is on screen.
// ---------------------------------------------------------------------------

const THUMB_EDGE = 320;

export function EntryIcon({ entry, size = 18 }: { entry: StoreEntry; size?: number }) {
  if (entry.kind === "folder") return <Folder className="shrink-0 text-amber-500" size={size} />;
  switch (entry.category) {
    case "image":
      return <ImageIcon className="shrink-0 text-cyan-600" size={size} />;
    case "video":
      return <Film className="shrink-0 text-rose-500" size={size} />;
    case "audio":
      return <Music className="shrink-0 text-violet-600" size={size} />;
    case "document":
      return <FileText className="shrink-0 text-cyan-600" size={size} />;
    case "archive":
      return <Archive className="shrink-0 text-amber-500" size={size} />;
    default:
      return <FileIcon className="shrink-0 text-ink-400" size={size} />;
  }
}

// One generation at a time: each one decrypts a whole file into memory.
let generationChain: Promise<unknown> = Promise.resolve();
const failedGeneration = new Set<string>();

function enqueue<T>(job: () => Promise<T>): Promise<T> {
  const run = generationChain.then(job, job);
  generationChain = run.catch(() => undefined);
  return run;
}

function canvasToJpeg(canvas: HTMLCanvasElement): Promise<Blob> {
  return new Promise((resolve, reject) =>
    canvas.toBlob((blob) => (blob ? resolve(blob) : reject(new Error("thumbnail encode failed"))), "image/jpeg", 0.82),
  );
}

function drawScaled(source: CanvasImageSource, width: number, height: number): HTMLCanvasElement {
  const scale = Math.min(1, THUMB_EDGE / Math.max(width, height));
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.round(width * scale));
  canvas.height = Math.max(1, Math.round(height * scale));
  const context = canvas.getContext("2d");
  if (!context) throw new Error("canvas unavailable");
  context.drawImage(source, 0, 0, canvas.width, canvas.height);
  return canvas;
}

async function imageFrame(url: string): Promise<HTMLCanvasElement> {
  const image = new Image();
  image.decoding = "async";
  image.src = url;
  await image.decode();
  return drawScaled(image, image.naturalWidth, image.naturalHeight);
}

function videoFrame(url: string): Promise<HTMLCanvasElement> {
  return new Promise((resolve, reject) => {
    const video = document.createElement("video");
    const timer = window.setTimeout(() => reject(new Error("video frame timed out")), 10_000);
    const finish = (action: () => void) => {
      window.clearTimeout(timer);
      action();
      video.removeAttribute("src");
      video.load();
    };
    video.muted = true;
    video.preload = "auto";
    video.onerror = () => finish(() => reject(new Error("video could not be decoded")));
    video.onloadeddata = () => {
      video.currentTime = Math.min(1, (video.duration || 0) / 10);
    };
    video.onseeked = () => {
      try {
        const canvas = drawScaled(video, video.videoWidth, video.videoHeight);
        finish(() => resolve(canvas));
      } catch (error) {
        finish(() => reject(error));
      }
    };
    video.src = url;
  });
}

function blobToBase64(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error);
    reader.onload = () => resolve(String(reader.result).split(",", 2)[1] ?? "");
    reader.readAsDataURL(blob);
  });
}

async function generateThumbnail(entry: StoreEntry): Promise<void> {
  const bytes = await vaultStore.preview(entry.id);
  const url = URL.createObjectURL(new Blob([bytes], { type: entry.contentType }));
  try {
    const canvas = entry.category === "video" ? await videoFrame(url) : await imageFrame(url);
    const jpeg = await canvasToJpeg(canvas);
    await vaultStore.setThumbnail(entry.id, await blobToBase64(jpeg));
  } finally {
    URL.revokeObjectURL(url);
  }
}

/**
 * The sealed thumbnail for a photo or video, made on first view when the
 * file can be previewed. Falls back to the type icon (HEIC and some codecs
 * cannot be decoded by the WebView — that is reported as no thumbnail, not
 * as a broken file).
 */
export function EntryThumbnail({
  entry,
  maxPreviewBytes,
  onThumbnailSaved,
  className = "",
}: {
  entry: StoreEntry;
  maxPreviewBytes: number;
  onThumbnailSaved?: (id: string) => void;
  className?: string;
}) {
  const [url, setUrl] = useState<string | null>(null);
  const visual = entry.kind === "file" && (entry.category === "image" || entry.category === "video");
  // A file kept in the cloud only is never downloaded just to draw a tile.
  const usable = entry.integrity !== "missing" && entry.integrity !== "failed" && (entry.availableOffline !== false || entry.hasThumbnail);

  useEffect(() => {
    if (!visual || !usable) return;
    let cancelled = false;
    let objectUrl: string | null = null;
    const show = (buffer: ArrayBuffer) => {
      if (cancelled) return;
      objectUrl = URL.createObjectURL(new Blob([buffer], { type: "image/jpeg" }));
      setUrl(objectUrl);
    };
    (async () => {
      try {
        if (entry.hasThumbnail) {
          show(await vaultStore.thumbnail(entry.id));
          return;
        }
        if (!canPreview(entry, maxPreviewBytes) || failedGeneration.has(entry.id)) return;
        await enqueue(() => (cancelled ? Promise.resolve() : generateThumbnail(entry)));
        if (cancelled) return;
        show(await vaultStore.thumbnail(entry.id));
        onThumbnailSaved?.(entry.id);
      } catch {
        failedGeneration.add(entry.id);
      }
    })();
    return () => {
      cancelled = true;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
      setUrl(null);
    };
    // Re-run only when the file itself changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entry.id, entry.hasThumbnail, visual, usable, maxPreviewBytes]);

  if (url) {
    return <img src={url} alt="" draggable={false} className={`h-full w-full object-cover ${className}`} />;
  }
  return (
    <div className={`flex h-full w-full items-center justify-center ${className}`}>
      <EntryIcon entry={entry} size={30} />
    </div>
  );
}
