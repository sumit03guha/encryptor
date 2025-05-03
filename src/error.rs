use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
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
