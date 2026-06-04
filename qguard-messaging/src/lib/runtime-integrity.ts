interface SecurityManifestAsset {
  path: string;
  bytes: number;
  sha256: string;
}

interface SecurityManifest {
  version: number;
  generated_at: string;
  algorithm: "SHA-256";
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

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Hex(bytes: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(digest));
}

async function fetchArrayBuffer(path: string): Promise<ArrayBuffer> {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`${path} returned ${response.status}`);
  return response.arrayBuffer();
}

export async function verifyRuntimeAssetIntegrity(): Promise<RuntimeAssetIntegrity> {
  try {
    const manifestResponse = await fetch("/security-manifest.json", { cache: "no-store" });
    if (!manifestResponse.ok) {
      return {
        status: "warning",
        verified: false,
        checked_assets: 0,
        failed_assets: [],
        generated_at: null,
        detail: "Security manifest is not available in this build",
      };
    }

    const manifest = await manifestResponse.json() as SecurityManifest;
    const failedAssets: string[] = [];
    for (const asset of manifest.assets) {
      const digest = await sha256Hex(await fetchArrayBuffer(asset.path));
      if (digest !== asset.sha256.toLowerCase()) failedAssets.push(asset.path);
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
