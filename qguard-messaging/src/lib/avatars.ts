// Shared avatar directory for Secure Chat and calls.
//
// One module-level cache serves every <UserAvatar> in the app: profile rows
// are fetched in per-tick batches (one query for a whole conversation list),
// each avatar blob is downloaded once per session through the authenticated
// storage client (RLS: only conversation peers / contacts can read it — see
// migration 028), and a single realtime subscription invalidates an entry
// when its owner uploads a new picture. Object URLs live for the session so
// re-entering a page never re-downloads.

import { useEffect, useSyncExternalStore } from "react";
import type { RealtimeChannel } from "@supabase/supabase-js";
import { isSupabaseConfigured, supabase } from "@/lib/supabase";

interface AvatarEntry {
  objectUrl: string | null;
  /** avatar_updated_at of the loaded blob; used to skip no-op invalidations. */
  version: string;
}

const cache = new Map<string, AvatarEntry>();
const pending = new Set<string>();
const queue = new Set<string>();
const listeners = new Set<() => void>();
let snapshotVersion = 0;
let flushTimer: number | null = null;
let realtimeChannel: RealtimeChannel | null = null;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function emit(): void {
  snapshotVersion += 1;
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  ensureRealtimeInvalidation();
  return () => listeners.delete(listener);
}

function getSnapshot(): number {
  return snapshotVersion;
}

async function loadAvatarBatch(userIds: string[]): Promise<void> {
  try {
    const { data, error } = await supabase
      .from("profiles")
      .select("id,avatar_storage_path,avatar_updated_at")
      .in("id", userIds);
    const rows = !error && Array.isArray(data) ? data : [];
    const byId = new Map(rows.map((row) => [String(row.id), row]));
    await Promise.all(userIds.map(async (userId) => {
      const row = byId.get(userId);
      const path = row?.avatar_storage_path ? String(row.avatar_storage_path) : null;
      const version = row?.avatar_updated_at ? String(row.avatar_updated_at) : "";
      if (!path) {
        cache.set(userId, { objectUrl: null, version });
        return;
      }
      const { data: blob, error: downloadError } = await supabase.storage
        .from("profile-avatars")
        .download(path);
      cache.set(userId, {
        objectUrl: !downloadError && blob ? URL.createObjectURL(blob) : null,
        version,
      });
    }));
  } catch {
    // Directory or storage unreachable: cache nothing so a later mount retries.
  } finally {
    userIds.forEach((userId) => pending.delete(userId));
    emit();
  }
}

function flushQueue(): void {
  flushTimer = null;
  const userIds = Array.from(queue);
  queue.clear();
  const toLoad = userIds.filter((userId) => !cache.has(userId) && !pending.has(userId));
  if (toLoad.length === 0) return;
  toLoad.forEach((userId) => pending.add(userId));
  void loadAvatarBatch(toLoad);
}

function requestAvatar(userId: string): void {
  if (!isSupabaseConfigured || !UUID_PATTERN.test(userId)) return;
  if (cache.has(userId) || pending.has(userId) || queue.has(userId)) return;
  queue.add(userId);
  if (flushTimer === null) flushTimer = window.setTimeout(flushQueue, 25);
}

/** Drop a user's cached avatar and re-download it (e.g. after a new upload). */
export function invalidateAvatar(userId: string): void {
  const entry = cache.get(userId);
  if (entry?.objectUrl) URL.revokeObjectURL(entry.objectUrl);
  cache.delete(userId);
  emit();
  requestAvatar(userId);
}

function ensureRealtimeInvalidation(): void {
  if (realtimeChannel || !isSupabaseConfigured) return;
  realtimeChannel = supabase
    .channel("qguard-avatar-directory")
    .on(
      "postgres_changes",
      { event: "UPDATE", schema: "public", table: "profiles" },
      (payload) => {
        const next = payload.new as { id?: string; avatar_updated_at?: string | null };
        const userId = next.id ? String(next.id) : "";
        const entry = cache.get(userId);
        if (!entry) return;
        const version = next.avatar_updated_at ? String(next.avatar_updated_at) : "";
        if (version !== entry.version) invalidateAvatar(userId);
      },
    )
    .subscribe();
}

/**
 * Resolve a user's avatar to a session-cached object URL, or null while it
 * loads / when they have no picture (callers render an initials fallback).
 */
export function useAvatarUrl(userId: string | null | undefined): string | null {
  useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
  useEffect(() => {
    if (userId) requestAvatar(userId);
  }, [userId]);
  return userId ? cache.get(userId)?.objectUrl ?? null : null;
}
