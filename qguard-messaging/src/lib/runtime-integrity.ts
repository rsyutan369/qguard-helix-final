import { coreSha3Hex } from "./core-crypto";

interface SecurityManifestAsset {
  path: string;
  bytes: number;
  sha3_256: string;
}

interface SecurityManifest {
  version: number;
  generated_at: string;
  algorithm: "SHA3-256";
  assets: SecurityManifestAsset[];
}

export interface RuntimeAssetIntegrity {
  status: "active" | "warning" | "failed";
  verified: boolean;
  checked_assets: number;
  failed_assets: string[];
  generated_at: string | null;
  detail: string;
}

async function fetchArrayBuffer(path: string): Promise<ArrayBuffer> {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`${path} returned ${response.status}`);
  return response.arrayBuffer();
}

export async function verifyRuntimeAssetIntegrity(): Promise<RuntimeAssetIntegrity> {
  try {
    const manifestResponse = await fetch("/security-manifest.json", { cache: "no-store" });
    // The dev server (and some asset protocols) answer unknown paths with the
    // SPA fallback: HTTP 200 + index.html. Parsing that as JSON used to throw
    // `Unexpected token '<'` and mark the check FAILED — but "no manifest" is
    // not tampering. The manifest is generated only by production builds
    // (vite.config.ts qguardSecurityManifest), so a missing/non-JSON response
    // is reported as an informational warning instead.
    const manifestText = manifestResponse.ok ? await manifestResponse.text() : "";
    if (!manifestResponse.ok || !manifestText.trim().startsWith("{")) {
      return {
        status: "warning",
        verified: false,
        checked_assets: 0,
        failed_assets: [],
        generated_at: null,
        detail: import.meta.env.DEV
          ? "Development build — the SHA3-256 asset manifest is generated for production builds only"
          : "Security manifest is not available in this build",
      };
    }

    const manifest = JSON.parse(manifestText) as SecurityManifest;
    const failedAssets: string[] = [];
    for (const asset of manifest.assets) {
      const digest = await coreSha3Hex(await fetchArrayBuffer(asset.path));
      if (digest !== asset.sha3_256?.toLowerCase()) failedAssets.push(asset.path);
    }

    return {
      status: failedAssets.length === 0 ? "active" : "failed",
      verified: failedAssets.length === 0,
      checked_assets: manifest.assets.length,
      failed_assets: failedAssets,
      generated_at: manifest.generated_at,
      detail: failedAssets.length === 0
        ? `${manifest.assets.length} web asset hash check${manifest.assets.length === 1 ? "" : "s"} verified`
        : `${failedAssets.length} web asset hash check${failedAssets.length === 1 ? "" : "s"} failed`,
    };
  } catch (error) {
    return {
      status: "failed",
      verified: false,
      checked_assets: 0,
      failed_assets: [],
      generated_at: null,
      detail: error instanceof Error ? error.message : "Runtime web asset integrity check failed",
    };
  }
}
