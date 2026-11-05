// Isolated build-environment verification. No app account, store or networking.
#[cfg(test)]
mod tests {
    use pqcrypto_traits::kem::{Ciphertext as _, SharedSecret as _};
    #[test]
    fn mlkem1024_roundtrip_and_corrupted_ciphertext() {
        use pqcrypto_mlkem::mlkem1024 as kem;
        let (pk, sk) = kem::keypair();
        let (shared, ciphertext) = kem::encapsulate(&pk);
        assert!(kem::decapsulate(&ciphertext, &sk).as_bytes() == shared.as_bytes());
        let mut altered = ciphertext.as_bytes().to_vec();
        altered[0] ^= 1;
        let altered = kem::Ciphertext::from_bytes(&altered).unwrap();
        assert!(kem::decapsulate(&altered, &sk).as_bytes() != shared.as_bytes());
    }
    #[test]
    fn mldsa65_signature_and_tamper_rejection() {
        use pqcrypto_mldsa::mldsa65 as sig;
        let (pk, sk) = sig::keypair();
        let signature = sig::detached_sign(b"local compiler validation", &sk);
        assert!(sig::verify_detached_signature(&signature, b"local compiler validation", &pk).is_ok());
        assert!(sig::verify_detached_signature(&signature, b"altered compiler validation", &pk).is_err());
    }
    #[test]
    fn mldsa87_signature_and_tamper_rejection() {
        use pqcrypto_mldsa::mldsa87 as sig;
        let (pk, sk) = sig::keypair();
        let signature = sig::detached_sign(b"local compiler validation", &sk);
        assert!(sig::verify_detached_signature(&signature, b"local compiler validation", &pk).is_ok());
        assert!(sig::verify_detached_signature(&signature, b"altered compiler validation", &pk).is_err());
    }
}
