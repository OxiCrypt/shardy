use super::{EncError, MAGIC_BYTES};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};
use std::{
    fs::File,
    io::{Read, Seek, Write},
    num::NonZero,
};
use zeroize::Zeroizing;
/// This function encrypts a file
pub fn encrypt_file(
    plaintext: &mut File,
    file: &mut File,
    key: &Zeroizing<[u8; 32]>,
    threshold: NonZero<u8>,
) -> Result<(), EncError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())?;
    let nonce = XChaCha20Poly1305::generate_nonce(OsRng);
    let mut aad = Vec::new();
    aad.extend_from_slice(&MAGIC_BYTES);
    aad.push(threshold.get());
    aad.extend_from_slice(nonce.as_slice());
    let mut plaintext_vec =
        Zeroizing::new(Vec::with_capacity(
            match usize::try_from(plaintext.metadata()?.len()) {
                Ok(n) => n,
                Err(_) => return Err(EncError::Encryption("Refusing to create sensitive buffer that will reallocate on 32-bit or lower system.".to_string()))
            }
        ));
    plaintext.rewind()?;
    plaintext.read_to_end(plaintext_vec.as_mut())?;
    let Ok(ciphertext) = cipher.encrypt(
        &nonce,
        Payload {
            msg: plaintext_vec.as_slice(),
            aad: &aad[..],
        },
    ) else {
        return Err(EncError::Encryption(
            "Encryption failed. That's all we know.".to_string(),
        ));
    };
    file.rewind()?;
    file.set_len(0)?;
    file.write_all(&MAGIC_BYTES)?;
    file.write_all(&[threshold.get()])?;
    file.write_all(nonce.as_slice())?;
    file.write_all(&ciphertext)?;
    Ok(())
}
