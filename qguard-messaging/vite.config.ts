import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import type { Plugin } from "vite";

const appRoot = __dirname;
const workspaceRoot = path.resolve(appRoot, "..");

const clientSupabaseEnvKeys = [
  "VITE_SUPABASE_URL",
  "VITE_SUPABASE_ANON_KEY",
  "VITE_SUPABASE_FALLBACK_URL",
  "VITE_SUPABASE_FALLBACK_ANON_KEY",
  "VITE_SUPABASE_USE_FALLBACK",
  "NEXT_PUBLIC_SUPABASE_URL",
  "NEXT_PUBLIC_SUPABASE_ANON_KEY",
  "NEXT_PUBLIC_SUPABASE_FALLBACK_URL",
  "NEXT_PUBLIC_SUPABASE_FALLBACK_ANON_KEY",
] as const;

type ClientSupabaseEnvKey = (typeof clientSupabaseEnvKeys)[number];

function cleanEnvValue(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  if (!trimmed) return undefined;
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1).trim() || undefined;
  }
  return trimmed;
}

function isUsableEnvValue(key: ClientSupabaseEnvKey, value: string | undefined): value is string {
  const cleaned = cleanEnvValue(value);
  if (!cleaned) return false;
  if (/^(your-|my_|change-me|placeholder)/i.test(cleaned)) return false;
  if (key === "VITE_SUPABASE_USE_FALLBACK") return /^(true|false)$/i.test(cleaned);
  if (key.endsWith("_URL")) return /^https:\/\/[^.]+\.supabase\.co$/i.test(cleaned);
  return cleaned.length > 20;
}

function readExampleEnv(filePath: string): Partial<Record<ClientSupabaseEnvKey, string>> {
  if (!fs.existsSync(filePath)) return {};
  const output: Partial<Record<ClientSupabaseEnvKey, string>> = {};
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);

  for (const line of lines) {
    const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (!match) continue;
    const key = match[1] as ClientSupabaseEnvKey;
    if (!clientSupabaseEnvKeys.includes(key)) continue;
    const value = cleanEnvValue(match[2]);
    if (isUsableEnvValue(key, value)) output[key] = value;
  }

  return output;
}

function resolveClientSupabaseEnv(mode: string): Partial<Record<ClientSupabaseEnvKey, string>> {
  const appEnv = loadEnv(mode, appRoot, "");
  const workspaceEnv = loadEnv(mode, workspaceRoot, "");
  const exampleEnv = readExampleEnv(path.join(workspaceRoot, ".env.example"));
  const resolved: Partial<Record<ClientSupabaseEnvKey, string>> = {};

  for (const key of clientSupabaseEnvKeys) {
    const candidates = [
      process.env[key],
      appEnv[key],
      workspaceEnv[key],
      exampleEnv[key],
    ];
    const value = candidates.find((candidate) => isUsableEnvValue(key, candidate));
    if (value) {
      resolved[key] = cleanEnvValue(value);
      process.env[key] = resolved[key];
    }
  }

  return resolved;
}

function defineClientEnv(env: Partial<Record<ClientSupabaseEnvKey, string>>) {
  return Object.fromEntries(
    Object.entries(env).map(([key, value]) => [`import.meta.env.${key}`, JSON.stringify(value)]),
  );
}

function collectBuildFiles(directory: string): string[] {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) return collectBuildFiles(fullPath);
    return [fullPath];
  });
}

function qguardSecurityManifest(): Plugin {
  return {
    name: "qguard-security-manifest",
    apply: "build",
    closeBundle() {
      const distDir = path.resolve(__dirname, "dist");
      const assets = collectBuildFiles(distDir)
        .map((filePath) => {
          const relativePath = path.relative(distDir, filePath).replace(/\\/g, "/");
          return { filePath, relativePath };
        })
        .filter(({ relativePath }) => /\.(?:js|css)$/i.test(relativePath))
        .map(({ filePath, relativePath }) => {
          const bytes = fs.readFileSync(filePath);
          return {
            path: `/${relativePath}`,
            bytes: bytes.length,
            sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
          };
        })
        .sort((a, b) => a.path.localeCompare(b.path));

      fs.writeFileSync(
        path.join(distDir, "security-manifest.json"),
        JSON.stringify({
          version: 1,
          generated_at: new Date().toISOString(),
          algorithm: "SHA-256",
          assets,
        }, null, 2),
      );
    },
  };
}

export default defineConfig(({ mode }) => {
  const clientEnv = resolveClientSupabaseEnv(mode);

  return {
    envDir: workspaceRoot,
    plugins: [react(), qguardSecurityManifest()],
    define: defineClientEnv(clientEnv),
    resolve: {
      alias: {
        "@": path.resolve(appRoot, "./src"),
      },
    },
    clearScreen: false,
    server: {
      port: 5174,
      strictPort: true,
    },
    envPrefix: ["VITE_", "NEXT_PUBLIC_", "TAURI_"],
    build: {
      outDir: "dist",
      target: process.env.TAURI_PLATFORM === "windows" ? "chrome105" : "safari13",
      minify: !process.env.TAURI_DEBUG ? "esbuild" : false,
      sourcemap: !!process.env.TAURI_DEBUG,
      reportCompressedSize: true,
    },
    esbuild: {
      legalComments: "none",
      drop: process.env.TAURI_DEBUG ? [] : ["debugger"],
    },
  };
});
