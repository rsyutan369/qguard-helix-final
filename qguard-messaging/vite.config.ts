import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import type { Plugin } from "vite";

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

export default defineConfig({
  plugins: [react(), qguardSecurityManifest()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
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
});
