//! This handles IO functionality to split shares and reduce monolithic-ness
use crate::MainError;
use regex::Regex;
use shardlib::Shares;
use std::fs::{self, File};
use std::io::{Read, Write};
use zeroize::Zeroize;

pub fn write_shares(shares: &Shares, share_prefix: &str) -> Result<(), MainError> {
    let share_vec = shares.as_vec();
    for (index, share_bytes) in share_vec.iter().enumerate() {
        let target = format!("{share_prefix}{index}.shds");
        let mut out = File::create(target).map_err(|_| {
            MainError::InvalidInput("Share creation failed, check permissions.".to_string())
        })?;
        out.write_all(share_bytes.as_ref()).map_err(|_| {
            MainError::InternalError("Share writing failed, interrupted.".to_string())
        })?;
    }
    Ok(())
}

pub fn get_shares(share_prefix: &str) -> Result<Shares, MainError> {
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

    let mut raw_shares: Vec<[u8; 65]> = Vec::with_capacity(files.len());
    for (i, mut file) in files.iter().enumerate() {
        let mut raw_bytes = [0u8; 65];
        file.read_exact(&mut raw_bytes)
            .map_err(|_| MainError::InternalError(format!("Failed to read share {i}")))?;
        raw_shares.push(raw_bytes);
        raw_bytes.zeroize();
    }

    Ok(Shares::from_slice(&raw_shares))
}
