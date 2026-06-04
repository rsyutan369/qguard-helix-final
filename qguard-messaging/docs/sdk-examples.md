# SDK Usage Examples

## Send A Message

```ts
await invoke("messaging_send_encrypted_message", {
  request: {
    conversationId: "conversation-id",
    recipientDeviceId: "device-id",
    plaintext: "Hello",
    kind: "Text",
  },
});
```

## Encrypt A Vault Object

```ts
await invoke("vault_encrypt_upload", {
  request: {
    fileName: "report.pdf",
    contentType: "application/pdf",
    plaintextBase64,
  },
});
```

## Verify A Safety Number

```ts
await invoke("security_verify_fingerprint", {
  remoteFingerprint,
});
```

