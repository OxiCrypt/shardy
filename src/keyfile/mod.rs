//! Tools related to the keyfile
use rand::fill;
use zeroize::Zeroizing;
// Generate a 32-byte random keyfile
pub fn gen_keyfile() -> Zeroizing<[u8; 32]> {
    let mut keybytes = Zeroizing::new([0u8; 32]);
    fill(keybytes.as_mut());
    keybytes
}
