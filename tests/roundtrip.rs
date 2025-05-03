use encryptor::{decrypt, encrypt};

/// Ensure we can encrypt and decrypt a message, and that
/// decryption fails with the wrong password.
#[test]
fn roundtrip() {
    let msg = "alice bob chloe";
    let pass = "Abc@1234";

    let blob = encrypt(msg, pass).expect("encryption must succeed");
    assert_eq!(msg, decrypt(&blob, pass).expect("decryption must succeed"));

    // A wrong password should give an error, not plaintext.
    assert!(decrypt(&blob, "wrong pass").is_err());
}
