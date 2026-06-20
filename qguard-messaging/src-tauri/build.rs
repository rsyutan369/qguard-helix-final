fn main() {
    // Recompile so compile-time hardening markers (option_env!) pick up new values
    // when the release pipeline sets them; otherwise cargo caches stale evidence.
    for var in [
        "QGUARD_EXPECTED_BINARY_SHA3",
        "QGUARD_SIGNED_BUILD",
        "QGUARD_RELEASE_ED25519_PUB",
        "QGUARD_CONTROL_FLOW_FLATTENING",
        "QGUARD_STRING_ENCRYPTION",
    ] {
        println!("cargo:rerun-if-env-changed={var}");
    }
    tauri_build::build();
}