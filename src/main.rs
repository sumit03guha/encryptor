use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};
use argon2::Argon2;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use thiserror::Error;

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;

const KEY_LEN: usize = 32;
type Key = [u8; KEY_LEN];

#[derive(Debug, Error)]
enum CryptoError {
    #[error("Argon2 error: {0}")]
    Argon2(String),

    #[error("Aes256Gcm error: {0}")]
    Aes256Gcm(String),

    #[error("Utf8 error: {0}")]
    Utf8(String),

    #[error("BaseUrl Decode error: {0}")]
    BaseUrlDecode(String),

    #[error("Decode error: {0}")]
    Decode(String),
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Key, CryptoError> {
    let mut key = [0u8; KEY_LEN];

    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| CryptoError::Argon2(e.to_string()))?;

    Ok(key)
}

fn encrypt(msg: &str, passphrase: &str) -> Result<String, CryptoError> {
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

fn decrypt(secret: &str, passphrase: &str) -> Result<String, CryptoError> {
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

fn main() -> Result<(), CryptoError> {
    let message = "alice bob chloe".to_string();
    let passphrase = "Abc@1234".to_string();

    let secret = encrypt(&message, &passphrase)?;
    println!("The secret is : {}", secret);

    let decrypted = decrypt(&secret, &passphrase)?;

    assert_eq!(&message, &decrypted, "Message don't match");

    let wrong_passphrase = "This is wrong passphrase".to_string();

    assert!(decrypt(&secret, &wrong_passphrase).is_err());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() -> Result<(), CryptoError> {
        let message = "alice bob chloe".to_string();
        let passphrase = "Abc@1234".to_string();

        let secret = encrypt(&message, &passphrase)?;
        let decrypted = decrypt(&secret, &passphrase)?;

        assert_eq!(&message, &decrypted, "Message don't match");

        let wrong_passphrase = "This is wrong passphrase".to_string();

        assert!(decrypt(&secret, &wrong_passphrase).is_err());

        Ok(())
    }
}
