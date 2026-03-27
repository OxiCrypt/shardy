//! Implements Encryption and Decryption
mod dc;
mod ec;
use crypto_common::InvalidLength;
pub use dc::decrypt_file;
pub use ec::encrypt_file;
/// Error for Encryption and Decryption. Opaque, as the ChaCha20 stuff is also opaque so no information is obtainable
pub struct EncError;
impl From<InvalidLength> for EncError {
    fn from(_: InvalidLength) -> Self {
        Self
    }
}
impl From<std::io::Error> for EncError {
    fn from(_: std::io::Error) -> Self {
        Self
    }
}
const MAGIC_BYTES: [u8; 4] = *b"shdy";
