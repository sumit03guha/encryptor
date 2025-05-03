use encryptor::{decrypt, encrypt};

#[test]
fn roundtrip() {
    let msg = "alice bob chloe";
    let pass = "Abc@1234";

    let blob = encrypt(msg, pass).unwrap();
    assert_eq!(decrypt(&blob, pass).unwrap(), msg);
    assert!(decrypt(&blob, "wrong pass").is_err());
}
