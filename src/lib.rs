#![forbid(unsafe_code)]
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]
//! # encryptor
//!
//! Encrypt a **Web3 wallet secret phrase** with an easy-to-remember password
//! and store only the resulting ciphertext string.
//!
//! * **KDF  ** [`Argon2id`](https://en.wikipedia.org/wiki/Argon2) — password → 256-bit key  
//! * **AEAD ** [`AES-256-GCM`](https://en.wikipedia.org/wiki/Galois/Counter_Mode) — key + nonce → authenticated ciphertext  
//! * **Blob** `[salt | nonce | ciphertext]` Base64URL-encoded (no padding)
//!
//! ```rust
//! use encryptor::{encrypt, decrypt};
//!
//! let phrase = "satoshi doll mercy …";      // wallet seed phrase
//! let pass   = "Fr33dom-2025!";             // memorable password
//!
//! let blob = encrypt(phrase, pass)?;        // store this string
//! assert_eq!(phrase, decrypt(&blob, pass)?);
//! # Ok::<(), encryptor::CryptoError>(())
//! ```
//!
//! ## Threat model
//! | ✅ Protects against            | ❌ Does **not** protect against               |
//! |--------------------------------|----------------------------------------------|
//! | Lost / stolen disk or backup   | Very weak or leaked passwords                |
//! | Curious cloud operator         | Attackers who can key-log or phish your pass |
//!
//! > **Security disclaimer:** *No formal audit yet.  Use at your own risk.*
//!
//! ---
//! ### API overview
//! * [`encrypt`] – passphrase → ciphertext string  
//! * [`decrypt`] – ciphertext string → original secret phrase  
//! * [`derive_key`] – raw Argon2id helper (mostly for advanced users)  
//! * [`CryptoError`] – unified error enum

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};
use argon2::Argon2;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

pub mod error;
pub use error::CryptoError;

/// Length in **bytes** of the random salt prepended to the ciphertext blob.
///
/// A 32-byte salt avoids collisions even at very high usage volumes.
pub const SALT_LEN: usize = 32;

/// Length in **bytes** of the AES-GCM nonce.
///
/// GCM requires a unique nonce per key; 96 bits (12 bytes) is the
/// recommended size and is what [`aes-gcm`] generates natively.
pub const NONCE_LEN: usize = 12;

/// Number of bytes in the derived symmetric key (`256 bits`).
pub const KEY_LEN: usize = 32;

/// In-memory representation of the 256-bit key returned by [`derive_key`].
///
/// The key is **not** automatically zeroed.  Consider wiping it manually
/// with the [`zeroize`](https://docs.rs/zeroize) crate if you hold it
/// longer than a local stack frame.
pub type Key = [u8; KEY_LEN];

/// Encrypt UTF-8 data with a **password**, returning a single Base64URL
/// string (`no = padding`) that embeds salt, nonce, and ciphertext.
///
/// The blob layout is  
/// `salt[32] | nonce[12] | ciphertext[variable]` → Base64URL.
///
/// ### Errors
/// * `CryptoError::Argon2`     – key derivation failed  
/// * `CryptoError::Aes256Gcm`  – encryption failure (rare)  
///
/// ### Example
/// ```rust
/// let blob = encryptor::encrypt("hello 🦀", "PwD!")?;
/// assert_ne!("hello 🦀", blob);
/// # Ok::<(), encryptor::CryptoError>(())
/// ```
pub fn encrypt(msg: &str, passphrase: &str) -> Result<String, CryptoError> {
    let mut salt = [0; SALT_LEN];
    let mut nonce = [0; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let key = derive_key(passphrase, &salt)?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| CryptoError::Aes256Gcm(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(nonce, msg.as_bytes())
        .map_err(|e| CryptoError::Aes256Gcm(e.to_string()))?;

    let mut blob = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ciphertext);

    Ok(BASE64_URL_SAFE_NO_PAD.encode(blob))
}

/// Decrypt a ciphertext produced by [`encrypt`].
///
/// If the password is wrong or the blob was tampered with, decryption
/// fails with `CryptoError::Aes256Gcm`.
///
/// ### Errors
/// * `CryptoError::BaseUrlDecode` – input was not valid Base64URL  
/// * `CryptoError::Decode`        – blob too short / malformed  
/// * `CryptoError::Argon2`        – key derivation failed  
/// * `CryptoError::Aes256Gcm`     – authentication failed (bad password)  
/// * `CryptoError::Utf8`          – plaintext not valid UTF-8  
///
/// ### Example
/// ```rust
/// # use encryptor::{encrypt, decrypt};
/// let blob = encrypt("secret", "pass")?;
/// assert_eq!("secret", decrypt(&blob, "pass")?);
/// assert!(decrypt(&blob, "wrong").is_err());
/// # Ok::<(), encryptor::CryptoError>(())
/// ```
pub fn decrypt(secret: &str, passphrase: &str) -> Result<String, CryptoError> {
    let decoded = BASE64_URL_SAFE_NO_PAD
        .decode(secret)
        .map_err(|e| CryptoError::BaseUrlDecode(e.to_string()))?;

    if decoded.len() < SALT_LEN + NONCE_LEN {
        return Err(CryptoError::Decode("Decoded token is too short".into()));
    }

    let (salt, rest) = decoded.split_at(SALT_LEN);
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);

    let key = derive_key(passphrase, salt)?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| CryptoError::Aes256Gcm(e.to_string()))?;

    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext.as_ref())
        .map_err(|e| CryptoError::Aes256Gcm(e.to_string()))?;

    String::from_utf8(plaintext).map_err(|e| CryptoError::Utf8(e.to_string()))
}

/// Derive a 256-bit symmetric key from a user **password** and random **salt**
/// using Argon2id.
///
/// ### Errors
/// * `CryptoError::Argon2` — underlying Argon2 implementation refused the
///   parameters (e.g. not enough memory on the host).
///
/// ### Example
/// ```rust, ignore
/// let salt = [0u8; SALT_LEN];
/// let key  = derive_key("correct horse battery staple", &salt)?;
/// assert_eq!(32, key.len());
/// # Ok::<(), encryptor::CryptoError>(())
/// ```
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Key, CryptoError> {
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| CryptoError::Argon2(e.to_string()))?;
    Ok(key)
}
