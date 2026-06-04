pub mod audit;
pub mod commands;
pub mod crypto;
pub mod device_trust;
pub mod error;
pub mod file_crypto;
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

use commands::auth::*;
use commands::devices::*;
use commands::keys::*;
use commands::messaging::*;
use commands::security::*;
use commands::telemetry::*;
use commands::vault::*;
use state::AppState;
use tauri::Manager;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "qguard_messaging=info".to_string()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let data_dir = dirs_fallback().join("qguard-messaging");
            let state = AppState::new(data_dir)?;
            app.manage(state);
            Ok(())
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
            vault_encrypt_upload,
            vault_decrypt_file_name,
            vault_download_decrypt,
            vault_share_file,
            vault_revoke_file_access,
            vault_verify_metadata,
            security_verify_fingerprint,
            security_report_key_change,
            security_export_report,
            security_hardening_status,
            security_quantum_report,
            telemetry_dashboard_snapshot,
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
