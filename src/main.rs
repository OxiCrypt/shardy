#![warn(clippy::pedantic)]
mod ecdc;
mod keyfile;
mod shamir;
use crate::shamir::ReconError;

use self::EncOrDec::{Decrypt, Encrypt};
use clap::{Parser, Subcommand};
use crypto_bigint::U512;
#[allow(unused_imports)]
#[allow(dead_code)]
use ecdc::{EncError, decrypt_file, encrypt_file};
use regex::Regex;
#[allow(unused_imports)]
use shamir::{reconstruct_secret_mod, shamir_split};
use std::io::{Read, Seek, SeekFrom};
use std::num::NonZero;
use std::path::PathBuf;
use std::{
    fs::{self, File},
    io::Write,
};
use zeroize::{Zeroize, Zeroizing};
#[derive(Parser)]
struct Shardy {
    #[arg(short, long)]
    input: PathBuf,
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[command(subcommand)]
    command: EncOrDec,
}
#[derive(Subcommand)]
enum EncOrDec {
    Encrypt {
        #[arg(short, long)]
        share_prefix: String,
        #[arg(short, long)]
        num_shares_out: NonZero<u8>,
        #[arg(short, long)]
        min_shares: NonZero<u8>,
    },
    Decrypt {
        #[arg(short, long)]
        share_prefix: String,
    },
}
impl EncOrDec {}
/// Represents error cases in main
enum MainError {
    /// Represents a error in the program
    InternalError(String),
    /// Represents stupid input that isn't usable for this program
    InvalidInput(String),
}
impl std::fmt::Debug for MainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MainError::InvalidInput(msg) | MainError::InternalError(msg) => write!(f, "{msg}"),
        }
    }
}
impl From<shamir::ReconError> for MainError {
    fn from(_: shamir::ReconError) -> Self {
        Self::InternalError("Error Reconstructing Key.".to_string())
    }
}
fn get_shares(share_prefix: &str) -> Result<Vec<File>, MainError> {
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

    Ok(files)
}
#[allow(clippy::too_many_lines)]
fn main() -> Result<(), MainError> {
    let cli_options = Shardy::parse();
    match cli_options.command {
        Encrypt {
            share_prefix,
            num_shares_out,
            min_shares,
        } => {
            if num_shares_out < min_shares {
                return Err(MainError::InvalidInput(
                "You must have more or the same amount of shares to export as the minimum share count."
                    .to_string(),
            ));
            }
            let keyfile = keyfile::gen_keyfile();
            let Ok(mut input_file) = File::open(&cli_options.input) else {
                return Err(MainError::InvalidInput("Invalid Path: Input".to_string()));
            };
            let Ok(mut output_file) = File::create(match cli_options.output {
                Some(o) => o,
                None => cli_options.input.with_added_extension("shdy"),
            }) else {
                return Err(MainError::InvalidInput("Invalid Path: Output".to_string()));
            };
            match encrypt_file(&mut input_file, &mut output_file, &keyfile, min_shares) {
                Ok(()) => (),
                Err(e) => {
                    return Err(MainError::InternalError(format!("{e:?}")));
                }
            }
            println!("Encryption Complete! Splitting Shares...");
            let Ok(shares) = shamir_split(min_shares, num_shares_out, &keyfile) else {
                return Err(MainError::InternalError(
                    "What did you do in GDB?".to_string(),
                ));
            };
            for (index, share) in shares.as_slice().iter().enumerate() {
                let mut to_write = [0u8; 65];
                to_write[0] = share.0;
                let slice_of_i = share.1.to_be_bytes();
                to_write[1..65].copy_from_slice(&slice_of_i.as_slice()[..(65 - 1)]);
                let target = format!("{share_prefix}{index}.shds");
                let Ok(mut out) = File::create(target) else {
                    return Err(MainError::InvalidInput(
                        "Something went wrong while creating a share. Most likely: Permissions."
                            .to_string(),
                    ));
                };
                if out.write(&to_write).is_err() {
                    return Err(MainError::InternalError(
                        "Failed to Write share, but share created. Most likely: Write interrupted."
                            .to_string(),
                    ));
                }
                to_write.zeroize();
            }
        }
        Decrypt { share_prefix } => {
            let shares = get_shares(&share_prefix)?;
            let mut shares_usable: Vec<(u8, U512)> = Vec::with_capacity(shares.len());
            for (i, mut rawshare) in shares.iter().enumerate() {
                if let Err(e) = rawshare.rewind() {
                    return Err(MainError::InternalError(format!(
                        "Failed to rewind share {i}. Error: {e}"
                    )));
                }
                let mut rawbytes = [0u8; 65];
                if rawshare.read_exact(&mut rawbytes).is_err() {
                    return Err(MainError::InternalError(format!(
                        "Failed to read share {i}"
                    )));
                }
                shares_usable.push((rawbytes[0], U512::from_be_slice(&rawbytes[1..65])));
                rawbytes.zeroize();
            }
            let Ok(mut ciphertext) = File::open(&cli_options.input) else {
                return Err(MainError::InternalError(
                    "Failed to open provided shdy file".to_string(),
                ));
            };
            if ciphertext.seek(SeekFrom::Start(4)).is_err() {
                return Err(MainError::InternalError(
                    "Failed to seek to threshold byte".to_string(),
                ));
            }

            let mut threshold = [0u8; 1];
            if ciphertext.read_exact(&mut threshold).is_err() {
                return Err(MainError::InternalError(
                    "Failed to read threshold byte".to_string(),
                ));
            }
            let key: Zeroizing<[u8; 32]> = Zeroizing::new(
                match reconstruct_secret_mod(shares_usable.as_slice(), threshold[0]) {
                    Ok(o) => o,
                    Err(e) => match e {
                        ReconError::DuplicateShares => {
                            return Err(MainError::InvalidInput("Duplicate Shares".to_string()));
                        }
                        ReconError::ModError => {
                            return Err(MainError::InternalError(
                                "Invariants failed. this is a bug on our end.".to_string(),
                            ));
                        }
                        ReconError::TooFewShares(r) => {
                            return Err(MainError::InvalidInput(format!(
                                "Too few shares. Need: {r}"
                            )));
                        }
                    },
                }
                .to_be_bytes()
                .as_slice()[32..]
                    .try_into()
                    .expect("32.. is always 32 long(the slice is 64 bytes long, 64-32=32"),
            );
            let Ok(mut output) = File::create(match cli_options.output {
                Some(o) => o,
                None => cli_options.input.with_extension(""),
            }) else {
                return Err(MainError::InternalError(
                    "Failed to create output file.".to_string(),
                ));
            };
            if let Err(e) = decrypt_file(&mut ciphertext, &mut output, &key) {
                return Err(MainError::InternalError(format!("{e:?}")));
            }
        }
    }
    Ok(())
}
