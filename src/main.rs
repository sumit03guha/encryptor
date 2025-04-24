fn encrypt(msg: &str, passphrase: &str) -> String {}

fn decrypt(secret: &str, passphrase: &str) -> String {}

fn main() {
    let message = "alice bob chloe".to_string();
    let passphrase = "Abc@1234".to_string();

    let secret = encrypt(&message, &passphrase);

    let decrypted = decrypt(&secret, &passphrase);

    assert_eq!(&message, &decrypted, "Message don't match");
}
