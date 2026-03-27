//! Tools related to the keyfile
use blake3::{Hash, hash};
use rand::fill;
use zeroize::Zeroizing;
// Generate a 64-byte random keyfile
pub fn gen_keyfile() -> Zeroizing<[u8; 64]> {
    let mut keybytes = Zeroizing::new([0u8; 64]);
    fill(keybytes.as_mut());
    keybytes
}
/// Hash a 64-byte keyfile
pub fn hash_keyfile(keyfile: &Zeroizing<[u8; 64]>) -> Hash {
    hash(keyfile.as_ref())
}
