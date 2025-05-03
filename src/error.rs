//! Cryptographic errors returned by this crate.
//!
//! All fallible functions expose their failure modes through
//!
//! ```rust,ignore
//! Result<T, CryptoError>
//! ```
//!
//! The variants wrap the underlying library’s error as a **plain string**
//! so that the public API stays stable even if the version of an
//! upstream crate changes.  You can inspect the message or display the
//! error with [`std::fmt::Display`].
//!
//! | Variant            | Origin crate | Typical cause                                                             |
//! |--------------------|--------------|---------------------------------------------------------------------------|
//! | `Argon2`           | `argon2`     | Key-derivation failed – e.g. invalid parameters or not enough memory.     |
//! | `Aes256Gcm`        | `aes-gcm`    | Encryption/decryption failure.  Most often: wrong password or tampering. |
//! | `Utf8`             | `std`        | Decrypted bytes were not valid UTF-8.                                     |
//! | `BaseUrlDecode`    | `base64`     | The ciphertext string was not valid Base64URL.                            |
//! | `Decode`           | internal     | The decoded blob had an unexpected length/format.                         |
//!
//! ## Example
//! ```rust
//! use encryptor::{encrypt, decrypt, CryptoError};
//!
//! match decrypt("bad blob", "pass") {
//!     Err(CryptoError::BaseUrlDecode(e)) => println!("Not Base64: {e}"),
//!     Err(e) => println!("Other error: {e}"),
//!     Ok(_)  => unreachable!("input was bad"),
//! }
//! ```
use thiserror::Error;

/// All error variants produced by [`encrypt`](crate::encrypt) and
/// [`decrypt`](crate::decrypt).
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Error reported by the **Argon2** key-derivation function.
    #[error("Argon2 error: {0}")]
    Argon2(String),

    /// Error bubbling up from **AES-256-GCM** encryption or decryption.
    ///
    /// For decryption this usually indicates an authentication failure
    /// (wrong password, corrupted or tampered blob).
    #[error("Aes256Gcm error: {0}")]
    Aes256Gcm(String),

    /// The decrypted plaintext could not be interpreted as UTF-8.
    #[error("Utf8 error: {0}")]
    Utf8(String),

    /// The supplied ciphertext was not valid **Base64URL** (no padding).
    #[error("BaseUrl Decode error: {0}")]
    BaseUrlDecode(String),

    /// The decoded blob was structurally invalid (e.g. too short to
    /// contain the expected salt + nonce).
    #[error("Decode error: {0}")]
    Decode(String),
}
