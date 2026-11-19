// Local Vite-only probe: runs the real avatar thumbnail code under the app's
// Content-Security-Policy (the page copies it from tauri.conf.json). The
// picture is a generated gradient, held as a blob: URL exactly like the
// profile picture the avatar directory downloads. Not part of dist.
import { avatarThumbnail } from "../src/lib/offline-avatars";

async function blobPicture(): Promise<string> {
  const canvas = document.createElement("canvas");
  canvas.width = 640;
  canvas.height = 480;
  const context = canvas.getContext("2d")!;
  const gradient = context.createLinearGradient(0, 0, 640, 480);
  gradient.addColorStop(0, "#7c3aed");
  gradient.addColorStop(1, "#0ea5e9");
  context.fillStyle = gradient;
  context.fillRect(0, 0, 640, 480);
  const blob = await new Promise<Blob>((resolve) => canvas.toBlob((value) => resolve(value!), "image/png"));
  return URL.createObjectURL(blob);
}

(window as unknown as { probe: () => Promise<unknown> }).probe = async () => {
  const url = await blobPicture();
  let fetchResult: string;
  try {
    await fetch(url);
    fetchResult = "allowed";
  } catch (error) {
    fetchResult = `refused: ${error instanceof Error ? error.message : String(error)}`;
  }
  try {
    const base64 = await avatarThumbnail(url);
    const bytes = atob(base64);
    return { fetchOfBlobUrl: fetchResult, thumbnailBytes: bytes.length, jpeg: bytes.charCodeAt(0) === 0xff && bytes.charCodeAt(1) === 0xd8 };
  } catch (error) {
    return { fetchOfBlobUrl: fetchResult, thumbnailError: error instanceof Error ? error.message : String(error) };
  }
};
