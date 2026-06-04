# API Documentation

The desktop app exposes Tauri commands. Supabase stores the relay schema in `supabase/migrations/001_secure_messaging.sql`.

## Auth

- `auth_register_user(request)`
- `auth_login(request)`
- `auth_logout()`
- `auth_sync_session(userId, email, tier)`

## Device Trust

- `devices_register_current_device(label)`
- `devices_list_trust_center()`
- `devices_verify_qr(remoteFingerprint)`
- `devices_approve_qr(request)`
- `devices_revoke(deviceId)`

## Keys

- `keys_upload_identity_bundle()`
- `keys_upload_signed_prekey()`
- `keys_upload_one_time_prekeys()`
- `keys_fetch_recipient_bundle(recipientUserId)`
- `keys_rotate_prekeys()`
- `keys_revoke_device(deviceId)`

## Messaging

- `messaging_send_encrypted_message(request)`
- `messaging_receive_encrypted_message(envelope)`
- `messaging_sync_queue()`
- `messaging_delete_encrypted_message(messageId)`
- `messaging_mark_delivery_receipt(messageId, recipientDeviceId, status)`

## Vault

- `vault_encrypt_upload(request)`
- `vault_download_decrypt(package)`
- `vault_share_file(fileId, recipientUserId, recipientDeviceId)`
- `vault_revoke_file_access(fileId, recipientDeviceId)`
- `vault_verify_metadata(package)`

## Security

- `security_verify_fingerprint(remoteFingerprint)`
- `security_report_key_change(deviceId, newFingerprint)`
- `security_export_report()`
- `security_quantum_report()`

