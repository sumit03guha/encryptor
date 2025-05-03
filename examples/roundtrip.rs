use encryptor::{CryptoError, decrypt, encrypt};

fn main() -> Result<(), CryptoError> {
    let msg = "alice bob chloe";
    let pass = "Abc@1234";

    let blob = encrypt(msg, pass)?;
    println!("Ciphertext: {}", blob);

    let back = decrypt(&blob, pass)?;
    println!("Plaintext : {}", back);
    Ok(())
}
