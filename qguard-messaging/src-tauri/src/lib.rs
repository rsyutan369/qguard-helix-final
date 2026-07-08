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
use commands::devices::*;
use commands::keys::*;
use commands::messaging::*;
use commands::security::*;
use commands::telemetry::*;
use commands::calls::*;
use commands::vault::*;
use commands::workspace::*;
use state::AppState;
use tauri::Manager;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let data_dir = dirs_fallback().join("qguard-messaging");

    // Force EVERY WebRTC media path onto software on Windows BEFORE the WebView2
    // environment is created. Hardware media pipelines can wedge flaky/outdated
    // GPU drivers (seen live on Intel Iris Xe 31.0.101.4502) so hard the whole
    // machine freezes without even a TDR event — only a power cut recovers it.
    // Disabling encode/decode alone was NOT enough: the camera-capture pipeline
    // (hardware MJPEG decode of webcam frames, D3D11 zero-copy Media Foundation
    // capture, GPU-memory frame buffers) and DirectComposition video overlays
    // still exercised the driver. Call media is capped to <=360p@24fps by default
    // (see call-quality.ts), so full software media costs little CPU; the app UI
    // itself stays GPU-composited and smooth. Respects an existing override.
    //
    // `--disable-features` REPLACES (not merges with) any earlier occurrence of
    // the switch, and the loader appends these env args after wry's programmatic
    // ones — so wry's own defaults (msWebOOUI, msPdfOOUI, msSmartScreenProtection)
    // must be repeated here to survive.
    #[cfg(target_os = "windows")]
    {
        // Self-healing: if the previous session died mid-call (machine froze,
        // hard restart), render everything in software from now on so the GPU
        // driver can never be wedged again. Cleared from Settings.
        let gpu_safe_mode = commands::calls::gpu_safe_mode_boot_check(&data_dir);
        if std::env::var_os("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS").is_none() {
            let mut args = String::from(concat!(
                "--disable-accelerated-video-decode ",
                "--disable-accelerated-video-encode ",
                "--disable-accelerated-mjpeg-decode ",
                "--disable-gpu-memory-buffer-video-frames ",
                "--disable-direct-composition-video-overlays ",
                "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection,MediaFoundationD3D11VideoCapture",
            ));
            if gpu_safe_mode {
                args.push_str(" --disable-gpu");
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

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        // Signed auto-updates (minisign pubkey + endpoints in tauri.conf.json)
        // and relaunch-after-update support.
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .setup(move |app| {
            let state = AppState::new(data_dir)?;
            app.manage(state);

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
            auth_register_user,
            auth_login,
            auth_logout,
            auth_sync_session,
            devices_register_current_device,
            devices_list_trust_center,
            devices_verify_qr,
            devices_approve_qr,
            devices_revoke,
            devices_delete,
            keys_upload_identity_bundle,
            keys_upload_signed_prekey,
            keys_upload_one_time_prekeys,
            keys_fetch_recipient_bundle,
            keys_unlock_private_key,
            keys_rotate_prekeys,
            keys_revoke_device,
            messaging_send_encrypted_message,
            messaging_receive_encrypted_message,
            messaging_sync_queue,
            messaging_delete_encrypted_message,
            messaging_mark_delivery_receipt,
            vault_encrypt_path,
            vault_decrypt_path,
            vault_encrypt_folder_path,
            vault_decrypt_folder_path,
            vault_delete_file,
            vault_recovery_status,
            vault_setup_recovery,
            vault_enable_recovery_with_phrase,
            vault_rewrap_path,
            vault_verify_path,
            vault_decrypt_path_with_recovery,
            vault_decrypt_folder_path_with_recovery,
            vault_decrypt_path_with_enterprise,
            vault_decrypt_folder_path_with_enterprise,
            workspace_status,
            workspace_setup_credential,
            workspace_unlock,
            workspace_lock,
            workspace_lock_all,
            workspace_reset_chat_lock,
            workspace_reset_vault,
            security_verify_fingerprint,
            security_report_key_change,
            security_export_report,
            security_hardening_status,
            security_quantum_report,
            telemetry_dashboard_snapshot,
            call_caller_setup,
            call_callee_setup,
            call_watchdog_begin,
            call_watchdog_end,
            call_gpu_safe_mode_status,
            call_gpu_safe_mode_clear,
            telemetry_recent_events
        ])
        .run(tauri::generate_context!())
        .expect("error running QGuard Messaging");
}

fn dirs_fallback() -> std::path::PathBuf {
    std::env::var_os("APPDATA")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(std::path::PathBuf::from))
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}
