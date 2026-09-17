pub mod audit;
pub mod commands;
pub mod crypto;
pub mod device_trust;
pub mod error;
pub mod fingerprints;
pub mod identity;
pub mod message_crypto;
pub mod messaging;
pub mod prekeys;
pub mod ratchet;
pub mod relay;
pub mod security;
pub mod state;
pub mod telemetry;
pub mod vault;
pub mod vault_stream;

use commands::auth::*;
use commands::applock::*;
use commands::billing::*;
use commands::devices::*;
use commands::keys::*;
use commands::messaging::*;
use commands::security::*;
use commands::calls::*;
use commands::vault::*;
use commands::vault_identity::*;
use commands::workspace::*;
use state::AppState;
use tauri::Manager;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Android runs the WebView and this Rust core in ONE process, so a panic
    // must never be silent — the tracing fmt layer below writes to stderr, which
    // Android drops. This routes any panic to logcat under a greppable tag so a
    // future occurrence is diagnosable in one step:  adb logcat -s QGuardPanic:E
    // (Pairs with `panic = "unwind"` in Cargo.toml, which keeps that panic from
    // taking the whole app down in the first place.)
    #[cfg(target_os = "android")]
    install_android_panic_logger();

    // On Android there is no APPDATA/HOME convention — the sandboxed app data
    // dir is only knowable from the app handle, so it is resolved in setup().
    #[cfg(not(mobile))]
    let data_dir = dirs_fallback().join("qguard-messaging");

    // WebView2 media-pipeline safety flags, set BEFORE the WebView2 environment
    // is created. The confirmed GPU-driver wedge (Intel Iris Xe 31.0.101.4502 —
    // whole machine froze with no TDR event; only a power cut recovered it) was
    // the CAMERA-CAPTURE path: hardware MJPEG decode of webcam frames, D3D11
    // zero-copy Media Foundation capture, GPU-memory frame buffers and
    // DirectComposition video overlays. Disabling encode/decode alone was NOT
    // enough back then, which localizes the fault to capture — so by default
    // only the capture path runs in software, while hardware VIDEO ENCODE and
    // DECODE stay ENABLED for production call quality (720p/1080p @ 30fps; the
    // old blanket software-everything launch starved the encoder on busy CPUs
    // and produced permanently blurry, macroblocked calls).
    //
    // Defense in depth stays layered:
    //   1. default  = software capture path + hardware codecs (this block);
    //   2. safe mode = the mid-call-crash watchdog (commands/calls.rs) flips the
    //      NEXT launch to full software media + `--disable-gpu`, exactly as
    //      before, until the user opts back in from Settings.
    //
    // `--disable-features` REPLACES (not merges with) any earlier occurrence of
    // the switch, and the loader appends these env args after wry's programmatic
    // ones — so wry's own defaults (msWebOOUI, msPdfOOUI, msSmartScreenProtection)
    // must be repeated here to survive. Respects an existing override.
    #[cfg(target_os = "windows")]
    {
        // Self-healing: if the previous session died mid-call (machine froze,
        // hard restart), render everything in software from now on so the GPU
        // driver can never be wedged again. Cleared from Settings.
        let gpu_safe_mode = commands::calls::gpu_safe_mode_boot_check(&data_dir);
        if std::env::var_os("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS").is_none() {
            let mut args = String::from(concat!(
                "--disable-accelerated-mjpeg-decode ",
                "--disable-gpu-memory-buffer-video-frames ",
                "--disable-direct-composition-video-overlays ",
                "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection,MediaFoundationD3D11VideoCapture",
            ));
            // Transport policy. This is the ONLY point at which the app can set
            // it: WebView2 fixes its network stack configuration when the
            // environment is created, and every Supabase request afterwards
            // rides that stack. See security::tls_policy for the platform scope
            // and the QGUARD_TLS_POLICY=compat escape hatch.
            args.push(' ');
            args.push_str(&security::tls_browser_arguments(&security::tls_policy()));
            if gpu_safe_mode {
                args.push_str(concat!(
                    " --disable-accelerated-video-decode",
                    " --disable-accelerated-video-encode",
                    " --disable-gpu",
                ));
            }
            std::env::set_var("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", args);
        }
    }

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "qguard_messaging=info".to_string()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init());

    // Signed auto-updates (minisign pubkey + endpoints in tauri.conf.json) and
    // relaunch-after-update support. Desktop-only: Android updates ship through
    // APK/Play distribution, and neither plugin compiles for mobile targets.
    #[cfg(desktop)]
    let builder = builder
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init());

    builder
        .setup(move |app| {
            #[cfg(mobile)]
            let data_dir = app
                .path()
                .app_data_dir()
                .map_err(|e| format!("resolve android app data dir: {e}"))?
                .join("qguard-messaging");
            let state = AppState::new(data_dir)?;
            app.manage(state);

            // Hash the running image now, on a background thread. It cannot
            // change while the process lives, so it is measured once — and
            // measuring it here keeps the read (tens of MB; the whole APK on
            // Android) off the main thread, where the synchronous
            // `security_hardening_status` command would otherwise do it.
            crate::security::prime_binary_measurement();

            // Task 9: Grant WebView2 camera + microphone permission on Windows
            // so getUserMedia works without a user-facing OS prompt blocking the call.
            #[cfg(target_os = "windows")]
            {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.with_webview(|webview| {
                        use webview2_com::PermissionRequestedEventHandler;
                        use webview2_com::Microsoft::Web::WebView2::Win32::COREWEBVIEW2_PERMISSION_STATE_ALLOW;
                        let controller = webview.controller();
                        if let Ok(core) = unsafe { controller.CoreWebView2() } {
                            let handler = PermissionRequestedEventHandler::create(
                                Box::new(|_sender, args| {
                                    use webview2_com::Microsoft::Web::WebView2::Win32::{
                                        COREWEBVIEW2_PERMISSION_KIND_CAMERA,
                                        COREWEBVIEW2_PERMISSION_KIND_MICROPHONE,
                                    };
                                    if let Some(args) = args {
                                        unsafe {
                                            // Only auto-grant the call's microphone + camera. All
                                            // other permission kinds fall through to the default
                                            // (prompt/deny) so we don't silently widen the surface.
                                            let mut kind = Default::default();
                                            if args.PermissionKind(&mut kind).is_ok()
                                                && (kind == COREWEBVIEW2_PERMISSION_KIND_MICROPHONE
                                                    || kind == COREWEBVIEW2_PERMISSION_KIND_CAMERA)
                                            {
                                                let _ = args.SetState(
                                                    COREWEBVIEW2_PERMISSION_STATE_ALLOW,
                                                );
                                            }
                                        }
                                    }
                                    Ok(())
                                }),
                            );
                            let mut token: i64 = 0;
                            unsafe {
                                let _ = core.add_PermissionRequested(&handler, &mut token);
                            }
                        }
                    });
                }
            }

            Ok(())
        })
        // A graceful quit during a live call must not trip the freeze watchdog:
        // frontend unmount effects are not guaranteed to run when the window is
        // destroyed, so the call-active marker is cleared here too.
        .on_window_event(|window, event| {
            if matches!(event, tauri::WindowEvent::CloseRequested { .. }) {
                let state = window.state::<AppState>();
                commands::calls::clear_call_marker(&state.data_dir);
            }
        })
        .invoke_handler(tauri::generate_handler![
            auth_logout,
            auth_sync_session,
            devices_list_trust_center,
            devices_verify_qr,
            devices_approve_qr,
            devices_revoke,
            devices_delete,
            keys_upload_identity_bundle,
            keys_upload_signed_prekey,
            keys_upload_one_time_prekeys,
            keys_replenish_one_time_prekeys,
            keys_unlock_private_key,
            keys_rotate_prekeys,
            keys_reset_device_identity,
            keys_ack_superseded_device,
            messaging_send_encrypted_message,
            messaging_receive_encrypted_message,
            messaging_delete_encrypted_message,
            vault_encrypt_path,
            vault_decrypt_path,
            vault_encrypt_folder_path,
            vault_decrypt_folder_path,
            vault_delete_file,
            vault_resolve_name,
            vault_default_encrypt_dest,
            vault_pick_folder,
            vault_describe_folder,
            vault_prepare_dest,
            vault_recovery_status,
            vault_setup_recovery,
            vault_enable_recovery_with_phrase,
            vault_rewrap_path,
            vault_verify_path,
            vault_decrypt_path_with_recovery,
            vault_decrypt_folder_path_with_recovery,
            vault_decrypt_path_with_enterprise,
            vault_decrypt_folder_path_with_enterprise,
            // Portable Hybrid Identity - seal containers to other people.
            vault_identity_generate,
            vault_identity_import,
            vault_identity_status,
            vault_identity_lock,
            vault_identity_export_public,
            vault_parse_recipient,
            vault_load_recipient_file,
            vault_seal_path,
            vault_seal_folder_path,
            vault_inspect_sealed,
            vault_open_sealed_path,
            vault_open_sealed_folder_path,
            workspace_status,
            workspace_setup_credential,
            workspace_unlock,
            workspace_lock,
            workspace_lock_all,
            workspace_reset_chat_lock,
            workspace_reset_vault,
            applock_status,
            applock_setup,
            applock_unlock,
            applock_update_session,
            applock_lock,
            applock_change_pin,
            applock_remove,
            applock_reset,
            applock_set_inactivity,
            applock_wipe,
            applock_device_integrity,
            security_verify_fingerprint,
            security_export_report,
            security_hardening_status,
            security_quantum_report,
            call_caller_setup,
            call_callee_setup,
            call_watchdog_begin,
            call_watchdog_end,
            call_gpu_safe_mode_status,
            call_gpu_safe_mode_clear,
            billing_platform,
            billing_state,
            billing_launch_purchase,
            billing_refresh_purchases,
            billing_open_checkout
        ])
        .run(tauri::generate_context!())
        .expect("error running QGuard Messaging");
}

#[cfg(not(mobile))]
fn dirs_fallback() -> std::path::PathBuf {
    std::env::var_os("APPDATA")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(std::path::PathBuf::from))
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

/// Route Rust panics to the Android log (`liblog`) so they are visible via
/// `adb logcat -s QGuardPanic:E`. Installed once, before the Tauri builder, and
/// chained to the default hook so normal panic output is preserved. `liblog` is
/// always present on Android and is linked explicitly in build.rs.
#[cfg(target_os = "android")]
fn install_android_panic_logger() {
    use std::sync::Once;

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            // android/util/Log priority ERROR == 6.
            const ANDROID_LOG_ERROR: std::os::raw::c_int = 6;
            extern "C" {
                fn __android_log_write(
                    prio: std::os::raw::c_int,
                    tag: *const std::os::raw::c_char,
                    text: *const std::os::raw::c_char,
                ) -> std::os::raw::c_int;
            }
            // CString::new only fails on an interior NUL, which a panic message
            // never contains; if it somehow does, we still fall through to the
            // default hook below rather than losing the panic entirely.
            if let (Ok(tag), Ok(text)) = (
                std::ffi::CString::new("QGuardPanic"),
                std::ffi::CString::new(format!("{info}")),
            ) {
                // SAFETY: liblog is linked (build.rs) and both pointers are valid
                // NUL-terminated C strings that outlive the call.
                unsafe { __android_log_write(ANDROID_LOG_ERROR, tag.as_ptr(), text.as_ptr()) };
            }
            previous(info);
        }));
    });
}
