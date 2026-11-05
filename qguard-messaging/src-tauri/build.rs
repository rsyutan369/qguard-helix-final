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
    // Declaring any rerun trigger turns off cargo's default "rerun on any package
    // file change", so the icons must be listed or a new logo keeps linking the
    // previous build's Windows icon resource into the exe.
    println!("cargo:rerun-if-changed=icons");

    // Android: link the platform log library (liblog) so the native panic
    // logger installed in lib.rs (which calls __android_log_write) resolves at
    // load time. Missing it would surface as an undefined-symbol failure when
    // the .so is loaded. build.rs runs on the host, so target is read from the
    // cargo-provided CARGO_CFG_TARGET_OS rather than a cfg! on this crate.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        println!("cargo:rustc-link-lib=dylib=log");
    }

    #[cfg(feature = "wolfcrypt")]
    wolfcrypt::build();

    tauri_build::build();
}

/// `--features wolfcrypt`: the cryptographic boundary (`crypto::provider`)
/// calls wolfCrypt through `wolfcrypt/qg_wolfcrypt.c`. See docs/FIPS_140_3.md.
#[cfg(feature = "wolfcrypt")]
mod wolfcrypt {
    use std::path::PathBuf;

    /// The wolfCrypt sources the boundary needs, compiled with
    /// `wolfcrypt/user_settings.h`.
    const SOURCES: &[&str] = &[
        "aes.c", "sha256.c", "sha512.c", "sha3.c", "hash.c", "hmac.c", "kdf.c", "pwdbased.c",
        "random.c", "memory.c", "wc_port.c", "error.c", "logging.c", "cpuid.c", "curve25519.c",
        "ed25519.c", "fe_operations.c", "ge_operations.c", "wc_mlkem.c", "wc_mlkem_poly.c",
        "wc_mldsa.c",
    ];

    pub fn build() {
        for var in ["WOLFSSL_DIR", "WOLFSSL_LIB_DIR", "WOLFSSL_INCLUDE_DIR"] {
            println!("cargo:rerun-if-env-changed={var}");
        }
        println!("cargo:rerun-if-changed=wolfcrypt");
        let mut build = cc::Build::new();
        build.define("WOLFSSL_USER_SETTINGS", None).file("wolfcrypt/qg_wolfcrypt.c");

        if let Some(lib_dir) = std::env::var_os("WOLFSSL_LIB_DIR") {
            // A prebuilt module, built as its own documentation prescribes (the
            // route for a FIPS 140-3 package). Its headers and the
            // user_settings.h it was built with come from WOLFSSL_INCLUDE_DIR.
            let include = std::env::var_os("WOLFSSL_INCLUDE_DIR")
                .expect("WOLFSSL_LIB_DIR is set: also set WOLFSSL_INCLUDE_DIR (headers + user_settings.h)");
            build.include(PathBuf::from(include));
            println!("cargo:rustc-link-search=native={}", PathBuf::from(lib_dir).display());
            println!("cargo:rustc-link-lib=wolfssl");
        } else {
            let source = PathBuf::from(
                std::env::var_os("WOLFSSL_DIR")
                    .expect("--features wolfcrypt needs WOLFSSL_DIR (a wolfSSL source tree) or WOLFSSL_LIB_DIR"),
            );
            build.include("wolfcrypt").include(&source).warnings(false);
            for file in SOURCES {
                build.file(source.join("wolfcrypt").join("src").join(file));
            }
        }
        build.compile("qguard_wolfcrypt");

        match std::env::var("CARGO_CFG_TARGET_OS").as_deref() {
            // wolfCrypt seeds its DRBG from the OS generator.
            Ok("windows") => {
                println!("cargo:rustc-link-lib=advapi32");
                println!("cargo:rustc-link-lib=bcrypt");
            }
            _ => {}
        }
    }
}