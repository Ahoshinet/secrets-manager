//! Security-critical crypto core for Secrets Manager.
//!
//! This crate performs **no I/O**. It only exposes pure functions over
//! RustCrypto primitives so the logic can be exhaustively unit-tested
//! (round-trip, AAD tamper detection, nonce uniqueness).
//!
//! Security invariants enforced here:
//! - Nonces are always freshly generated from the OS CSPRNG (`OsRng`),
//!   24 bytes, never reused / fixed / counter-based.
//! - Master keys live in [`Zeroizing`] memory and are wiped on drop.
//! - No secret material (keys, plaintext, tokens) ever appears in
//!   `Debug`/`Display`/error messages.
//! - Token comparison is constant-time via `subtle`.

#![forbid(unsafe_code)]

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Length of the XChaCha20-Poly1305 nonce, in bytes.
pub const NONCE_LEN: usize = 24;
/// Length of the derived master key, in bytes.
pub const KEY_LEN: usize = 32;

/// Errors surfaced by this crate.
///
/// Intentionally carries **no** secret-dependent data: variants map to
/// fixed strings so nothing sensitive can leak through logs or responses.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key derivation failed")]
    Kdf,
    #[error("invalid kdf parameters")]
    Params,
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
    #[error("invalid nonce length")]
    NonceLen,
}

/// Argon2id cost parameters. Persisted in the DB so the exact settings
/// used at init are always available for verification and rekey.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Iteration (time) cost.
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
}

impl KdfParams {
    /// Hardened defaults (memory-hard): m = 256 MiB, t = 4, p = 1.
    ///
    /// Chosen deliberately over the spec baseline (64 MiB) because the
    /// deployment prioritizes safety over startup speed.
    pub const STRONG: Self = Self {
        m_cost_kib: 256 * 1024,
        t_cost: 4,
        p_cost: 1,
    };
}

// Deliberately no `Debug` derive (would print the params, which is fine,
// but we keep the type minimal and explicit).

/// A derived 32-byte master key held in zeroizing memory.
///
/// The inner bytes are wiped on drop. `Debug` is implemented manually to
/// redact the material so the key can never be printed by accident.
pub struct MasterKey(Zeroizing<[u8; KEY_LEN]>);

impl MasterKey {
    /// Borrow the raw key bytes. Callers must not copy or log these.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Wrap raw bytes (used by tests and rekey paths).
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        MasterKey(Zeroizing::new(bytes))
    }
}

impl core::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

/// Derive a 32-byte master key from a passphrase using Argon2id.
///
/// `salt` should be a stable, randomly-generated value stored in the DB.
pub fn derive_key(
    passphrase: &SecretString,
    salt: &[u8],
    params: KdfParams,
) -> Result<MasterKey, CryptoError> {
    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| CryptoError::Params)?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(passphrase.expose_secret().as_bytes(), salt, out.as_mut_slice())
        .map_err(|_| CryptoError::Kdf)?;

    Ok(MasterKey(out))
}

/// Build the associated data (AAD) bound to a ciphertext.
///
/// Uses length-prefixed encoding so that distinct `(project, key)` pairs
/// can never collide (e.g. `("a","bc")` vs `("ab","c")`). This binds each
/// ciphertext to its record, defeating cross-record swaps.
pub fn aad_bytes(project: &str, key: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + project.len() + key.len());
    v.extend_from_slice(&(project.len() as u32).to_le_bytes());
    v.extend_from_slice(project.as_bytes());
    v.extend_from_slice(&(key.len() as u32).to_le_bytes());
    v.extend_from_slice(key.as_bytes());
    v
}

/// Encrypt `plaintext` under `key` with a fresh random nonce.
///
/// Returns `(nonce, ciphertext_with_tag)`. The nonce is always newly
/// generated from `OsRng`.
pub fn encrypt(
    key: &MasterKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.expose()));

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Encrypt)?;

    Ok((nonce.to_vec(), ciphertext))
}

/// Decrypt a ciphertext produced by [`encrypt`]. Fails on any tag or AAD
/// mismatch without revealing why.
pub fn decrypt(
    key: &MasterKey,
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::NonceLen);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.expose()));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::Decrypt)
}

/// Generate a fresh random salt (16 bytes) from the OS CSPRNG.
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// SHA-256 of a token string. Only the hash is ever persisted.
pub fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Constant-time byte equality. Returns `false` for differing lengths
/// (length itself is not secret here).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Generate a new high-entropy token (256-bit) encoded as URL-safe
/// base64 (no padding). Shown to the operator exactly once.
pub fn generate_token() -> SecretString {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    raw.zeroize();
    SecretString::from(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> MasterKey {
        MasterKey::from_bytes([7u8; KEY_LEN])
    }

    #[test]
    fn roundtrip_matches() {
        let key = test_key();
        let aad = aad_bytes("cdn", "DATABASE_URL");
        let plaintext = b"postgres://user:pass@host/db";

        let (nonce, ct) = encrypt(&key, plaintext, &aad).unwrap();
        assert_eq!(nonce.len(), NONCE_LEN);
        // Ciphertext must not contain the plaintext.
        assert!(!ct.windows(plaintext.len()).any(|w| w == plaintext));

        let out = decrypt(&key, &nonce, &ct, &aad).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn aad_tamper_is_detected() {
        let key = test_key();
        let aad = aad_bytes("projA", "KEY");
        let (nonce, ct) = encrypt(&key, b"secret", &aad).unwrap();

        // Swapped project name -> must fail.
        let wrong_project = aad_bytes("projB", "KEY");
        assert!(decrypt(&key, &nonce, &ct, &wrong_project).is_err());

        // Swapped key name -> must fail.
        let wrong_key = aad_bytes("projA", "KEY2");
        assert!(decrypt(&key, &nonce, &ct, &wrong_key).is_err());
    }

    #[test]
    fn aad_length_prefix_prevents_collision() {
        // ("a","bc") and ("ab","c") must produce different AAD.
        assert_ne!(aad_bytes("a", "bc"), aad_bytes("ab", "c"));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = test_key();
        let aad = aad_bytes("p", "k");
        let (nonce, mut ct) = encrypt(&key, b"hello", &aad).unwrap();
        ct[0] ^= 0xFF;
        assert!(decrypt(&key, &nonce, &ct, &aad).is_err());
    }

    #[test]
    fn nonces_are_unique() {
        let key = test_key();
        let aad = aad_bytes("p", "k");
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let (nonce, _) = encrypt(&key, b"x", &aad).unwrap();
            assert!(seen.insert(nonce), "nonce reuse detected");
        }
    }

    #[test]
    fn wrong_nonce_length_rejected() {
        let key = test_key();
        let aad = aad_bytes("p", "k");
        let (_n, ct) = encrypt(&key, b"x", &aad).unwrap();
        assert!(matches!(
            decrypt(&key, &[0u8; 12], &ct, &aad),
            Err(CryptoError::NonceLen)
        ));
    }

    #[test]
    fn ct_eq_behaves() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn hash_token_is_deterministic() {
        assert_eq!(hash_token("tok"), hash_token("tok"));
        assert_ne!(hash_token("tok"), hash_token("tok2"));
        assert_eq!(hash_token("tok").len(), 32);
    }

    #[test]
    fn generate_token_is_random_and_hashable() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a.expose_secret(), b.expose_secret());
        // Non-empty, URL-safe base64 of 32 bytes.
        assert!(a.expose_secret().len() >= 43);
    }

    #[test]
    fn derive_key_deterministic_and_salt_sensitive() {
        // Use cheap params for the test to keep it fast.
        let params = KdfParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let pass = SecretString::from("correct horse battery staple".to_string());
        let k1 = derive_key(&pass, b"salt-0001-16byte", params).unwrap();
        let k2 = derive_key(&pass, b"salt-0001-16byte", params).unwrap();
        assert_eq!(k1.expose(), k2.expose());

        let k3 = derive_key(&pass, b"salt-0002-16byte", params).unwrap();
        assert_ne!(k1.expose(), k3.expose());
    }

    #[test]
    fn master_key_debug_is_redacted() {
        let key = test_key();
        assert_eq!(format!("{key:?}"), "MasterKey(<redacted>)");
    }
}
