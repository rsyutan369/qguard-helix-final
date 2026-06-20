//! Hardened-release integrity tool.
//!
//! Usage (run from the workspace, via the release script or directly):
//!   cargo run --release --example release_integrity -- keygen
//!   cargo run --release --example release_integrity -- pubkey <private-hex>
//!   cargo run --release --example release_integrity -- sign <exe-path> <private-hex>
//!
//! `sign` computes the SHA3-256 of the built executable, signs that hash with
//! the Ed25519 release private key, and writes `release.integrity.json` beside
//! the executable. The runtime (security::hardening_status) re-derives the hash,
//! reads the manifest, and verifies both the hash and the signature against the
//! release public key embedded at build time (QGUARD_RELEASE_ED25519_PUB).
use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("keygen") => keygen(),
        Some("pubkey") => pubkey(args.get(2).map(String::as_str)),
        Some("sign") => sign(args.get(2).map(String::as_str), args.get(3).map(String::as_str)),
        _ => {
            eprintln!("usage: release_integrity keygen | pubkey <private-hex> | sign <exe> <private-hex>");
            std::process::exit(2);
        }
    }
}

fn parse_private(hex_str: &str) -> ed25519_dalek::SigningKey {
    let bytes: [u8; 32] = hex::decode(hex_str.trim())
        .expect("private key must be valid hex")
        .try_into()
        .expect("private key must be exactly 32 bytes");
    ed25519_dalek::SigningKey::from_bytes(&bytes)
}

fn keygen() {
    let signing = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    println!("private_hex={}", hex::encode(signing.to_bytes()));
    println!("public_hex={}", hex::encode(signing.verifying_key().to_bytes()));
}

fn pubkey(private_hex: Option<&str>) {
    let signing = parse_private(private_hex.expect("private key hex required"));
    println!("public_hex={}", hex::encode(signing.verifying_key().to_bytes()));
}

fn sign(exe: Option<&str>, private_hex: Option<&str>) {
    use ed25519_dalek::Signer;
    use sha3::{Digest, Sha3_256};

    let exe = exe.expect("executable path required");
    let signing = parse_private(private_hex.expect("private key hex required"));
    let exe_bytes = std::fs::read(exe).expect("read executable");
    let sha3 = hex::encode(Sha3_256::digest(&exe_bytes));
    let signature = signing.sign(sha3.as_bytes());

    let manifest = serde_json::json!({
        "binary_sha3": sha3,
        "signature": hex::encode(signature.to_bytes()),
        "public_key": hex::encode(signing.verifying_key().to_bytes()),
        "built_at": chrono::Utc::now().to_rfc3339(),
    });
    let dir = std::path::Path::new(exe)
        .parent()
        .expect("executable has a parent directory");
    let out = dir.join("release.integrity.json");
    let mut file = std::fs::File::create(&out).expect("create release.integrity.json");
    file.write_all(serde_json::to_string_pretty(&manifest).unwrap().as_bytes())
        .expect("write release.integrity.json");
    println!("wrote {}", out.display());
    println!("binary_sha3={sha3}");
    println!("public_hex={}", hex::encode(signing.verifying_key().to_bytes()));
}