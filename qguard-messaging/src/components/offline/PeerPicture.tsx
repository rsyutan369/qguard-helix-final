import { useState, type ReactNode } from "react";
import { useOfflineAvatar } from "@/lib/offline-avatars";

/**
 * A trusted device's profile picture (or this account's, with `fingerprint`
 * null), filling its rounded container. Shows `fallback` until the picture
 * has synced, when the user has none, or if it fails to render.
 */
export function PeerPicture({ fingerprint, digest, fallback }: {
  fingerprint: string | null | undefined; digest: string | null | undefined; fallback: ReactNode;
}) {
  const url = useOfflineAvatar(fingerprint, digest);
  const [failed, setFailed] = useState<string | null>(null);
  if (!url || url === failed) return <>{fallback}</>;
  return <img src={url} alt="" draggable={false} onError={() => setFailed(url)}
    style={{ display: "block", width: "100%", height: "100%", objectFit: "cover", borderRadius: "inherit" }} />;
}
