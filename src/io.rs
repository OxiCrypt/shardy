//! This handles IO functionality to split shares and reduce monolithic-ness
use crate::MainError;
use crate::shamir::Shares;
use crypto_bigint::U512;
use regex::Regex;
use std::fs::{self, File};
use std::io::{Read, Seek, Write};
use zeroize::Zeroize;
pub fn write_shares(shares: &Shares, share_prefix: &str) -> Result<(), MainError> {
    for (index, share) in shares.as_slice().iter().enumerate() {
        let mut to_write = [0u8; 65];
        to_write[0] = share.0;
        let slice_of_i = share.1.to_be_bytes();
        to_write[1..65].copy_from_slice(&slice_of_i.as_slice()[..(65 - 1)]);
        let target = format!("{share_prefix}{index}.shds");
        let mut out = File::create(target).map_err(|_| {
            MainError::InvalidInput("Share creation failed, check permissions.".to_string())
        })?;
        out.write(&to_write).map_err(|_| {
            MainError::InternalError("Share writing failed, interrupted.".to_string())
        })?;
        to_write.zeroize();
    }
    Ok(())
}
pub fn get_shares(share_prefix: &str) -> Result<Vec<(u8, U512)>, MainError> {
    let pattern = format!(r"^{}[0-9]+\.shds$", regex::escape(share_prefix));

    let Ok(re) = Regex::new(&pattern) else {
        return Err(MainError::InvalidInput(
            "Bad Regex for share_prefix".to_string(),
        ));
    };
    let mut files = Vec::new();

    for entry in match fs::read_dir(".") {
        Ok(o) => o,
        Err(_) => return Err(MainError::InternalError("No permissions".to_string())),
    } {
        let Ok(entry) = entry else {
            return Err(MainError::InternalError("Failed to read file".to_string()));
        };
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();

        if re.is_match(&file_name) {
            files.push(match File::open(entry.path()) {
                Ok(o) => o,
                Err(_) => {
                    return Err(MainError::InternalError(
                        "Error opening share. Permissions are likely.".to_string(),
                    ));
                }
            });
        }
    }
    let mut shares_usable: Vec<(u8, U512)> = Vec::with_capacity(files.len());
    for (i, mut rawshare) in files.iter().enumerate() {
        if let Err(e) = rawshare.rewind() {
            return Err(MainError::InternalError(format!(
                "Failed to rewind share {i}. Error: {e}"
            )));
        }
        let mut rawbytes = [0u8; 65];
        rawshare
            .read_exact(&mut rawbytes)
            .map_err(|_| MainError::InternalError(format!("Failed to read share {i}")))?;
        shares_usable.push((rawbytes[0], U512::from_be_slice(&rawbytes[1..65])));
        rawbytes.zeroize();
    }
    Ok(shares_usable)
}
