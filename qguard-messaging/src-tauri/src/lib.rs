pub mod audit;
pub mod call_log;
pub mod commands;
pub mod crypto;
pub mod device_trust;
pub mod error;
pub mod fingerprints;
pub mod identity;
pub mod message_crypto;
pub mod device_pins;
pub mod history_backup;
pub mod message_keys;
pub mod messaging;
pub mod pq_ratchet;
#[cfg(test)]
pub(crate) mod test_support;
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
use commands::downloads::*;
use commands::keys::*;
use commands::messaging::*;
use commands::nearby::*;
use commands::outbox::*;
use commands::privacy::*;
use commands::recovery::*;
use commands::security::*;
use commands::assistant::*;
use commands::call_log::*;
use commands::calls::*;
use commands::account_key::*;
use commands::channels::*;
use commands::conversation_names::*;
use commands::contact_verification::*;
use commands::crypto_module::*;
use commands::vault::*;
use commands::vault_identity::*;
use commands::vault_store::*;
use commands::vault_cloud::*;
use commands::vault_hidden::*;
use commands::vault_library::*;
use commands::vault_share::*;
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
            // The device's FIPS approved-mode choice, before any credential is
            // sealed; and the module's known-answer self-tests, off the main
            // thread, so the first keyed operation rarely waits for them.
            crate::crypto::provider::set_approved_mode(state.fips_approved_mode_setting());
            std::thread::spawn(|| {
                let _ = crate::crypto::provider::self_test_report();
            });
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
                // Message keys recorded since the last periodic write would
                // otherwise be lost with the process; losing them only costs a
                // repeat decrypt, but there is no reason to pay it.
                state.flush_loaded_message_keys();
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
            devices_assess_pins,
            devices_approve_pins,
            keys_upload_identity_bundle,
            keys_upload_signed_prekey,
            keys_upload_one_time_prekeys,
            keys_replenish_one_time_prekeys,
            keys_unlock_private_key,
            keys_rotate_prekeys,
            keys_prekey_status,
            keys_purge_retired_prekeys,
            keys_reset_device_identity,
            keys_ack_superseded_device,
            messaging_send_encrypted_message,
            messaging_receive_encrypted_message,
            messaging_delete_encrypted_message,
            messaging_cache_envelope_key,
            messaging_message_keys_lookup,
            messaging_flush_message_keys,
            messaging_forget_message_keys,
            messaging_ratchet_status,
            messaging_set_ratchet_enabled,
            messaging_reset_ratchet_session,
            contact_verification_status,
            contact_mark_verified,
            contact_clear_verification,
            contact_pairing_offer,
            contact_pairing_receive,
            contact_assurance,
            call_phrase,
            call_phrase_check,
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
            // Quantum Vault Storage - the managed on-device encrypted library.
            vault_store_status,
            vault_store_list,
            vault_store_activity,
            vault_store_import,
            vault_store_import_folder,
            vault_store_path_kind,
            vault_store_disk_usage,
            vault_store_create_folder,
            vault_store_rename,
            vault_store_move,
            vault_store_set_favorite,
            vault_store_trash,
            vault_store_restore,
            vault_store_purge,
            vault_store_empty_trash,
            vault_store_verify,
            vault_store_verify_all,
            vault_store_preview,
            vault_store_export,
            vault_store_export_folder,
            vault_store_set_thumbnail,
            vault_store_thumbnail,
            vault_store_start_fresh,
            // Quantum Vault cloud backup (phase 2) - ciphertext only.
            vault_cloud_state,
            vault_cloud_set_enabled,
            vault_cloud_delete_backup,
            vault_cloud_plan,
            vault_cloud_record_sync,
            vault_cloud_prepare_file,
            vault_cloud_prepare_share_copy,
            vault_cloud_release_share_copy,
            vault_cloud_prepare_index,
            vault_cloud_read_part,
            vault_cloud_complete_upload,
            vault_cloud_discard_upload,
            vault_cloud_complete_delete,
            vault_cloud_download_begin,
            vault_cloud_download_part,
            vault_cloud_restore_open_index,
            vault_cloud_restore_file,
            vault_cloud_restore_end,
            // Quantum Vault phase 3 - one library across the account's devices.
            vault_library_status,
            vault_library_create,
            vault_library_rotate,
            vault_library_make_wrap,
            vault_library_accept_wrap,
            vault_library_recovery_envelope,
            vault_library_mark_recovery_stored,
            vault_library_accept_recovery,
            vault_library_merge,
            vault_library_prepare_publish,
            vault_library_published,
            // Quantum Vault phase 4 - secure sharing.
            vault_share_seal,
            vault_share_open,
            vault_share_preview,
            vault_share_save,
            // Hidden vaults - opened only by their pattern (vault::hidden).
            vault_hidden_status,
            vault_hidden_list,
            vault_hidden_import,
            vault_hidden_create_folder,
            vault_hidden_rename,
            vault_hidden_move,
            vault_hidden_delete,
            vault_hidden_preview,
            vault_hidden_export,
            vault_hidden_lock,
            vault_hidden_destroy,
            vault_hidden_erase_all,
            vault_hidden_set_duress,
            vault_hidden_recovery_setup,
            vault_hidden_recovery_remove,
            call_log_record,
            call_log_list,
            call_log_missed_count,
            call_log_mark_seen,
            call_log_delete,
            call_log_clear,
            workspace_status,
            workspace_setup_credential,
            workspace_unlock,
            vault_pattern_unlock,
            vault_hidden_create,
            vault_hidden_open,
            vault_hidden_recovery_check,
            vault_hidden_recover,
            workspace_remove_credential,
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
            applock_set_duress_pin,
            applock_clear_duress_pin,
            applock_biometric_status,
            applock_biometric_enable,
            applock_biometric_unlock,
            applock_biometric_disable,
            privacy_recents_masking_status,
            privacy_set_recents_masking,
            privacy_panic_wipe,
            privacy_screen_seal,
            privacy_screen_verify,
            privacy_screen_verify_legacy,
            privacy_screen_kdf,
            crypto_module_status,
            crypto_set_approved_mode,
            crypto_digest,
            crypto_hmac_sha3_256,
            crypto_attachment_seal,
            crypto_attachment_open,
            history_backup_export,
            history_backup_import,
            social_recovery_setup,
            social_recovery_hold_share,
            social_recovery_held,
            social_recovery_request,
            social_recovery_request_code,
            social_recovery_release,
            social_recovery_finish,
            assistant_key_status,
            assistant_key_set,
            assistant_key_clear,
            assistant_key_for_request,
            account_key_status,
            account_key_bootstrap,
            account_key_rotate,
            account_key_make_wrap,
            account_key_accept_wrap,
            account_field_seal,
            account_field_open_many,
            channel_status,
            channel_new_epoch,
            channel_key_export,
            channel_key_import,
            channel_mark_distributed,
            channel_seal_post,
            channel_open_post,
            channel_forget,
            conversation_names_list,
            conversation_names_remember,
            conversation_names_forget,
            outbox_put,
            outbox_list,
            outbox_remove,
            nearby_status,
            nearby_start,
            nearby_stop,
            nearby_request_permissions,
            nearby_send,
            nearby_clear_outgoing,
            nearby_take_received,
            security_verify_fingerprint,
            security_export_report,
            security_hardening_status,
            security_quantum_report,
            call_caller_setup,
            call_callee_prepare,
            call_callee_setup,
            call_watchdog_begin,
            call_watchdog_end,
            call_gpu_safe_mode_status,
            call_gpu_safe_mode_clear,
            billing_platform,
            billing_state,
            billing_launch_purchase,
            billing_refresh_purchases,
            billing_open_checkout,
            downloads_save_begin,
            downloads_save_chunk,
            downloads_save_commit,
            downloads_save_abort
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
