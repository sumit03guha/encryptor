# encryptor

[![Crates.io](https://img.shields.io/crates/v/encryptor.svg)](https://crates.io/crates/encryptor)
[![Docs.rs](https://docs.rs/encryptor/badge.svg)](https://docs.rs/encryptor)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Encrypt a **Web3 wallet secret phrase** with an easy-to-remember password
and store only the resulting ciphertext string.

* **KDF** [`Argon2id`](https://en.wikipedia.org/wiki/Argon2) — password → 256-bit key
* **AEAD** [`AES-256-GCM`](https://en.wikipedia.org/wiki/Galois/Counter_Mode) — key + nonce → authenticated ciphertext
* **Blob** `[salt | nonce | ciphertext]` Base64URL-encoded (no padding)

```rust
use encryptor::{encrypt, decrypt};

let phrase = "satoshi doll mercy …";      // wallet seed phrase
let pass   = "Fr33dom-2025!";             // memorable password

let blob = encrypt(phrase, pass)?;        // store this string
assert_eq!(phrase, decrypt(&blob, pass)?);
```

## Threat model

| ✅ Protects against            | ❌ Does **not** protect against               |
|--------------------------------|----------------------------------------------|
| Lost / stolen disk or backup   | Very weak or leaked passwords                |
| Curious cloud operator         | Attackers who can key-log or phish your pass |

> **Security disclaimer:** *No formal audit yet.  Use at your own risk.*

---

## API overview

* [`encrypt`] – passphrase → ciphertext string
* [`decrypt`] – ciphertext string → original secret phrase
* [`CryptoError`] – unified error enum
