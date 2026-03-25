use rand::fill;
use zeroize::Zeroizing;
pub fn gen_keyfile() -> Zeroizing<[u8; 32]> {
    let mut keybytes = Zeroizing::new([0u8; 32]);
    fill(keybytes.as_mut());
    keybytes
}
