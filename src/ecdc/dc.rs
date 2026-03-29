use super::{EncError, MAGIC_BYTES};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use std::{
    fs::File,
    io::{Read, Seek, Write},
};
use zeroize::Zeroizing;
/// This function decrypts a file.
pub fn decrypt_file(
    ciphertext: &mut File,
    output: &mut File,
    key: &Zeroizing<[u8; 32]>,
) -> Result<(), EncError> {
    let mut ciphertext_vec = Zeroizing::new(Vec::new());
    ciphertext.rewind()?;
    ciphertext.read_to_end(ciphertext_vec.as_mut())?;
    if !ciphertext_vec.as_slice().starts_with(&MAGIC_BYTES) {
        return Err(EncError);
    }
    #[allow(clippy::no_effect_underscore_binding)]
    let nonce: &XNonce = XNonce::from_slice(&ciphertext_vec[8..32]);
    let salt = &ciphertext_vec.as_slice()[32..48];
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())?;
    let mut aad = Vec::new();
    aad.extend_from_slice(&MAGIC_BYTES);
    aad.extend_from_slice(nonce.as_slice());
    aad.extend_from_slice(salt);
    let Ok(plaintext) = cipher.decrypt(
        nonce,
        Payload {
            msg: &ciphertext_vec[48..],
            aad: &aad[..],
        },
    ) else {
        return Err(EncError);
    };
    output.rewind()?;
    output.set_len(0)?;
    output.write_all(&plaintext[..])?;
    Ok(())
}
