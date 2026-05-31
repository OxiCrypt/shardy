//! Implements Encryption and Decryption
mod dc;
mod ec;
use crypto_common::InvalidLength;
pub use dc::decrypt_file;
pub use ec::encrypt_file;
/// Error for Encryption and Decryption. Opaque, as the `ChaCha20` stuff is also opaque so no information is obtainable
#[derive(Debug)]
#[allow(dead_code)]
pub enum EncError {
    Encryption(String),
    Io(std::io::Error),
}
impl From<InvalidLength> for EncError {
    fn from(_: InvalidLength) -> Self {
        Self::Encryption("Invalid Length of key.".to_string())
    }
}
impl From<std::io::Error> for EncError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
const MAGIC_BYTES: [u8; 4] = *b"shdy";
