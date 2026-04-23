use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::prelude::*;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

#[derive(Clone)]
pub struct TunnelCipher {
    cipher: XChaCha20Poly1305,
}

impl TunnelCipher {
    pub fn from_key_file(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = fs::read(path.as_ref())
            .with_context(|| format!("failed to read key file {}", path.as_ref().display()))?;
        let key = parse_key_bytes(&bytes)?;
        Ok(Self::from_key_bytes(key))
    }

    pub fn from_key_bytes(key: [u8; KEY_LEN]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(Key::from_slice(&key)),
        }
    }

    pub fn encrypt(&self, aad: &[u8], plaintext: &[u8]) -> Result<EncryptedPayload> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .context("frame encryption failed")?;
        Ok(EncryptedPayload { nonce, ciphertext })
    }

    pub fn decrypt(&self, aad: &[u8], encrypted: &EncryptedPayload) -> Result<Vec<u8>> {
        self.cipher
            .decrypt(
                XNonce::from_slice(&encrypted.nonce),
                Payload {
                    msg: encrypted.ciphertext.as_slice(),
                    aad,
                },
            )
            .context("frame authentication failed")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPayload {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

fn parse_key_bytes(bytes: &[u8]) -> Result<[u8; KEY_LEN]> {
    if bytes.len() == KEY_LEN {
        return bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid raw key length"));
    }

    let trimmed = std::str::from_utf8(bytes)
        .context("key file is neither 32 raw bytes nor valid text")?
        .trim();

    if trimmed.len() == KEY_LEN * 2 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let decoded = hex::decode(trimmed).context("failed to decode hex key")?;
        return decoded
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("hex key must decode to 32 bytes"));
    }

    let decoded = BASE64_STANDARD
        .decode(trimmed)
        .context("key must be 32 raw bytes, 64 hex characters, or base64 for 32 bytes")?;
    if decoded.len() != KEY_LEN {
        bail!("decoded key must be exactly 32 bytes");
    }
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("decoded key must be exactly 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_key() {
        let parsed =
            parse_key_bytes(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap();
        assert_eq!(parsed[0], 0);
        assert_eq!(parsed[31], 31);
    }

    #[test]
    fn decrypt_rejects_wrong_key() {
        let cipher = TunnelCipher::from_key_bytes([7; 32]);
        let wrong = TunnelCipher::from_key_bytes([8; 32]);
        let encrypted = cipher.encrypt(b"aad", b"secret").unwrap();
        assert!(wrong.decrypt(b"aad", &encrypted).is_err());
    }

    #[test]
    fn decrypt_rejects_tampering() {
        let cipher = TunnelCipher::from_key_bytes([7; 32]);
        let mut encrypted = cipher.encrypt(b"aad", b"secret").unwrap();
        encrypted.ciphertext[0] ^= 1;
        assert!(cipher.decrypt(b"aad", &encrypted).is_err());
    }
}
