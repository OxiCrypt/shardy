use super::{EncError, MAGIC_BYTES};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload, rand_core::RngCore},
};
use std::{
    fs::File,
    io::{Read, Seek, Write},
};
use zeroize::Zeroizing;
/// This function encrypts a file
pub fn encrypt_file(
    plaintext: &mut File,
    file: &mut File,
    key: &Zeroizing<[u8; 32]>,
) -> Result<(), EncError> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())?;
    let nonce = XChaCha20Poly1305::generate_nonce(OsRng);
    let mut aad = Vec::new();
    aad.extend_from_slice(&MAGIC_BYTES);
    aad.extend_from_slice(nonce.as_slice());
    aad.extend_from_slice(&salt);
    let mut plaintext_vec = Zeroizing::new(Vec::new());
    plaintext.rewind()?;
    plaintext.read_to_end(plaintext_vec.as_mut())?;
    let Ok(ciphertext) = cipher.encrypt(
        &nonce,
        Payload {
            msg: plaintext_vec.as_slice(),
            aad: &aad[..],
        },
    ) else {
        return Err(EncError);
    };
    file.rewind()?;
    file.set_len(0)?;
    file.write_all(&MAGIC_BYTES)?;
    file.write_all(nonce.as_slice())?;
    file.write_all(&salt)?;
    file.write_all(&ciphertext)?;
    Ok(())
}
