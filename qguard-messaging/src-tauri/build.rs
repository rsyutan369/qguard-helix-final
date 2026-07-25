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

    // Android: link the platform log library (liblog) so the native panic
    // logger installed in lib.rs (which calls __android_log_write) resolves at
    // load time. Missing it would surface as an undefined-symbol failure when
    // the .so is loaded. build.rs runs on the host, so target is read from the
    // cargo-provided CARGO_CFG_TARGET_OS rather than a cfg! on this crate.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        println!("cargo:rustc-link-lib=dylib=log");
    }

    tauri_build::build();
}