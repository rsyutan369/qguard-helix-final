# Security Limitations

- This implementation is production-oriented, not independently audited.
- The current ratchet module is a Double Ratchet-style foundation and should be reviewed before regulated production deployment.
- Supabase sees minimum routing metadata such as recipient IDs and queue timing.
- The relay cannot decrypt content, but compromised endpoints can access local plaintext after decryption.
- Secure deletion cannot be guaranteed on all SSDs.
- Optional liboqs support is a feature-gated integration point, not the default dependency path.

