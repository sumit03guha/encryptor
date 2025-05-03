use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};
use argon2::Argon2;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
pub mod error;
pub use error::CryptoError;
pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

const KEY_LEN: usize = 32;
pub type Key = [u8; KEY_LEN];

pub fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Key, CryptoError> {
    let mut key = [0u8; KEY_LEN];

    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| CryptoError::Argon2(e.to_string()))?;

    Ok(key)
}

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
        .encrypt(&nonce, msg.as_bytes())
        .map_err(|e| CryptoError::Aes256Gcm(e.to_string()))?;

    let mut blob: Vec<u8> = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);

    Ok(BASE64_URL_SAFE_NO_PAD.encode(blob))
}

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
        .decrypt(&Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|e| CryptoError::Aes256Gcm(e.to_string()))?;

    Ok(String::from_utf8(plaintext).map_err(|e| CryptoError::Utf8(e.to_string()))?)
}
