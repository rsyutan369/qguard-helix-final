# Device Trust Model

Every user can have multiple devices, and every device has its own identity bundle and prekeys.

New devices begin as pending. Approval requires QR verification or signed approval from an existing trusted device. The UI surfaces:

- This device
- Trusted
- Pending QR approval
- Suspicious
- Revoked

Messages are encrypted separately for each recipient device. Group messaging v1 uses per-recipient-device fanout rather than shared sender keys.

