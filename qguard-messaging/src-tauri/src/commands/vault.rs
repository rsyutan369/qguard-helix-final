use serde::{Deserialize, Serialize};
use tauri::State;

use crate::crypto::hybrid_kex::LocalKemKeypair;
use crate::crypto::signatures::LocalSigningKeypair;
use crate::error::{QGuardError, Result};
use crate::file_crypto::{
    decrypt_file_name_for_device, encrypt_file_for_device, verify_file_metadata,
    EncryptedFilePackage, EncryptionContext,
};
use crate::state::AppState;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultEncryptRequest {
    pub file_name: String,
    pub content_type: String,
    pub plaintext_base64: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct VaultShareGrant {
    pub file_id: String,
    pub recipient_user_id: String,
    pub recipient_device_id: String,
    pub status: String,
}

#[tauri::command]
pub fn vault_encrypt_upload(
    state: State<'_, AppState>,
    request: VaultEncryptRequest,
) -> Result<EncryptedFilePackage> {
    let identity_bundle = state.ensure_identity(&state.user_id()?, "Windows Desktop")?;
    let owner_user_id = state.user_id()?;
    let plaintext = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(request.plaintext_base64)
            .map_err(|e| QGuardError::InvalidInput(format!("invalid base64: {e}")))?
    };
    let identity = state
        .identity
        .lock()
        .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?;
    let identity = identity
        .as_ref()
        .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?;
    let signer = LocalSigningKeypair {
        ed25519_secret: identity.signing.ed25519_secret,
        ed25519_public: identity.signing.ed25519_public.clone(),
        mldsa_secret: identity.signing.mldsa_secret.clone(),
        mldsa_public: identity.signing.mldsa_public.clone(),
    };
    let recipient = (
        &identity.kem.x25519_public[..],
        &identity.kem.mlkem_public[..],
    );
    let package = encrypt_file_for_device(
        &request.file_name,
        &request.content_type,
        &plaintext,
        EncryptionContext {
            owner_user_id,
            owner_device_id: identity_bundle.device_id.clone(),
        },
        &identity_bundle.device_id,
        recipient,
        &signer,
    )?;
    state.touch_telemetry(
        "vault",
        "File encrypted locally; upload should store ciphertext only",
        100,
    );
    state.audit_info(
        "vault_encrypt_upload",
        "Quantum vault package prepared for Supabase Storage",
    );
    Ok(package)
}

#[tauri::command]
pub fn vault_download_decrypt(
    state: State<'_, AppState>,
    package: EncryptedFilePackage,
) -> Result<String> {
    state.require_auth()?;
    let session_user_id = state.user_id()?;
    state.ensure_identity(&session_user_id, "Windows Desktop")?;
    state.check_decrypt_rate_limit("vault_file", &package.metadata.file_id, 8, 300)?;
    let identity = state
        .identity
        .lock()
        .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?;
    let identity = identity
        .as_ref()
        .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?;
    let recipient = LocalKemKeypair {
        x25519_secret: identity.kem.x25519_secret,
        x25519_public: identity.kem.x25519_public.clone(),
        mlkem_secret: identity.kem.mlkem_secret.clone(),
        mlkem_public: identity.kem.mlkem_public.clone(),
    };
    let plaintext = crate::file_crypto::decrypt_file_for_device(
        &package,
        &identity.device_id,
        &recipient,
        EncryptionContext {
            owner_user_id: identity.user_id.clone(),
            owner_device_id: identity.device_id.clone(),
        },
    )?;
    state.touch_telemetry(
        "vault_decrypt",
        "Client-side vault decrypt completed with local key material",
        100,
    );
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(plaintext))
}

#[tauri::command]
pub fn vault_decrypt_file_name(
    state: State<'_, AppState>,
    package: EncryptedFilePackage,
) -> Result<String> {
    state.require_auth()?;
    let session_user_id = state.user_id()?;
    state.ensure_identity(&session_user_id, "Windows Desktop")?;
    state.check_decrypt_rate_limit("vault_filename", &package.metadata.file_id, 24, 300)?;
    let identity = state
        .identity
        .lock()
        .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?;
    let identity = identity
        .as_ref()
        .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?;
    let recipient = LocalKemKeypair {
        x25519_secret: identity.kem.x25519_secret,
        x25519_public: identity.kem.x25519_public.clone(),
        mlkem_secret: identity.kem.mlkem_secret.clone(),
        mlkem_public: identity.kem.mlkem_public.clone(),
    };
    decrypt_file_name_for_device(
        &package,
        &identity.device_id,
        &recipient,
        EncryptionContext {
            owner_user_id: identity.user_id.clone(),
            owner_device_id: identity.device_id.clone(),
        },
    )
}

#[tauri::command]
pub fn vault_share_file(
    state: State<'_, AppState>,
    file_id: String,
    recipient_user_id: String,
    recipient_device_id: String,
) -> Result<VaultShareGrant> {
    state.require_auth()?;
    state.audit_info("vault_share", "Encrypted file grant created");
    Ok(VaultShareGrant {
        file_id,
        recipient_user_id,
        recipient_device_id,
        status: "granted_ciphertext_only".to_string(),
    })
}

#[tauri::command]
pub fn vault_revoke_file_access(
    state: State<'_, AppState>,
    file_id: String,
    recipient_device_id: String,
) -> Result<VaultShareGrant> {
    state.require_auth()?;
    state.audit_info("vault_revoke", "Encrypted file grant revoked");
    Ok(VaultShareGrant {
        file_id,
        recipient_user_id: "revoked".to_string(),
        recipient_device_id,
        status: "revoked".to_string(),
    })
}

#[tauri::command]
pub fn vault_verify_metadata(
    state: State<'_, AppState>,
    package: EncryptedFilePackage,
) -> Result<bool> {
    state.require_auth()?;
    verify_file_metadata(&package)?;
    Ok(true)
}
