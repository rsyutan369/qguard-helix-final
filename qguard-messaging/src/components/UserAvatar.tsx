// Circular user avatar with a deterministic initials fallback.
//
// Resolves the picture through the shared avatar directory (lib/avatars.ts),
// so any number of instances cost one profile query + one download per user
// per session. While loading — or for users with no picture / no visibility
// (avatars are only readable by conversation peers and contacts) — it renders
// initials on a gradient derived from the user id, so the same person always
// gets the same color everywhere in the app.

import { useEffect, useState } from "react";
import { useAvatarUrl } from "@/lib/avatars";

const GRADIENTS = [
  "linear-gradient(135deg, #8b5cf6, #7c3aed)", // violet
  "linear-gradient(135deg, #06b6d4, #0284c7)", // cyan
  "linear-gradient(135deg, #10b981, #0d9488)", // emerald
  "linear-gradient(135deg, #f59e0b, #ea580c)", // amber
  "linear-gradient(135deg, #f43f5e, #db2777)", // rose
  "linear-gradient(135deg, #6366f1, #2563eb)", // indigo
];

function hashOf(seed: string): number {
  let hash = 0;
  for (let i = 0; i < seed.length; i += 1) hash = (hash * 31 + seed.charCodeAt(i)) >>> 0;
  return hash;
}

function gradientFor(seed: string): string {
  return GRADIENTS[hashOf(seed) % GRADIENTS.length];
}

function initialsFor(name: string): string {
  const parts = name.trim().split(/[\s@._-]+/).filter(Boolean);
  const letters = parts.slice(0, 2).map((part) => part[0]);
  if (letters.length === 1 && parts[0].length > 1) letters.push(parts[0][1]);
  return letters.join("").toUpperCase() || "QG";
}

export function UserAvatar({ userId, name, size = 40, className = "" }: {
  userId: string | null | undefined;
  name: string;
  size?: number;
  className?: string;
}) {
  const url = useAvatarUrl(userId);
  const [broken, setBroken] = useState(false);
  useEffect(() => setBroken(false), [url]);

  const dimension = { width: size, height: size };
  if (url && !broken) {
    return (
      <img
        src={url}
        alt={name}
        title={name}
        loading="lazy"
        draggable={false}
        onError={() => setBroken(true)}
        className={`shrink-0 select-none rounded-full object-cover ${className}`}
        style={dimension}
      />
    );
  }
  return (
    <div
      title={name}
      aria-label={name}
      // `data-avatar-tone` is the same deterministic hash reduced to two
      // buckets, so a skin with a single accent (Android/Modernist) can still
      // give each person a stable identity. The gradient below stays the
      // fallback, which is what every other build renders.
      data-avatar-tone={hashOf(userId || name) % 2}
      className={`flex shrink-0 select-none items-center justify-center rounded-full font-bold text-white ${className}`}
      style={{
        ...dimension,
        background: `var(--qg-avatar-bg, ${gradientFor(userId || name)})`,
        fontSize: Math.max(10, Math.round(size * 0.34)),
      }}
    >
      {initialsFor(name)}
    </div>
  );
}
