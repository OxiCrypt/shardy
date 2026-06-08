#![warn(clippy::pedantic)]
mod io;
use self::EncOrDec::{Decrypt, Encrypt};
use clap::{Parser, Subcommand};
use io::{get_shares, write_shares};
use shardlib::{ShamirError, decrypt_bytes, encrypt_bytes};
use std::fs;
use std::io::Write;
use std::num::NonZero;
use std::path::PathBuf;

const MAGIC: &[u8; 4] = b"shdy";
const MAGIC_LEN: usize = 4;
const THRESHOLD_LEN: usize = 1;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = MAGIC_LEN + THRESHOLD_LEN + NONCE_LEN; // 29

#[derive(Parser)]
#[command(name = "shardy")]
#[command(about = "Encrypts using random key, then splits into shares.")]
#[command(version)]
struct Shardy {
    #[arg(short, long, help = "File to be en/decrypted")]
    input: PathBuf,
    #[arg(short, long, help = "En/decrypted file")]
    output: Option<PathBuf>,
    #[command(subcommand)]
    command: EncOrDec,
}

#[derive(Subcommand)]
enum EncOrDec {
    #[command(about = "Encrypt and split key into shares")]
    Encrypt {
        #[arg(short, long, help = "Prefix of generated shares' names")]
        share_prefix: String,
        #[arg(short, long, help = "Number of shares to export")]
        num_shares_out: NonZero<u8>,
        #[arg(short, long, help = "Number of shares required to decrypt.")]
        min_shares: NonZero<u8>,
    },
    #[command(about = "Recover key from shares and decrypt")]
    Decrypt {
        #[arg(short, long, help = "Prefix of share filenames.")]
        share_prefix: String,
    },
}

enum MainError {
    InternalError(String),
    InvalidInput(String),
}

impl std::fmt::Debug for MainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MainError::InvalidInput(msg) | MainError::InternalError(msg) => write!(f, "{msg}"),
        }
    }
}

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
                    "You must have more or the same amount of shares to export \
                     as the minimum share count."
                        .to_string(),
                ));
            }
            let plaintext = fs::read(&cli_options.input)
                .map_err(|_| MainError::InvalidInput("Invalid Path: Input".to_string()))?;
            let encrypted =
                encrypt_bytes(&plaintext, min_shares, num_shares_out).map_err(|e| match e {
                    shardlib::Error::Shamir(s) => match s {
                        ShamirError::TooFewShares(n) => {
                            MainError::InvalidInput(format!("Too few shares. Need: {n}"))
                        }
                        ShamirError::ModError => {
                            MainError::InternalError("Shamir modulus error.".to_string())
                        }
                        ShamirError::DuplicateShares => {
                            MainError::InternalError("Duplicate shares generated.".to_string())
                        }
                        ShamirError::KeyExtraction => {
                            MainError::InternalError("Key extraction error.".to_string())
                        }
                    },
                    shardlib::Error::ObviousContradiction => {
                        MainError::InvalidInput("Something went VERY WRONG.".to_string())
                    }
                    shardlib::Error::EncryptionError => {
                        MainError::InternalError("Encryption failed.".to_string())
                    }
                    shardlib::Error::DecryptionError => {
                        MainError::InternalError("Unexpected decryption error.".to_string())
                    }
                })?;

            let output_path = cli_options
                .output
                .unwrap_or_else(|| cli_options.input.with_added_extension("shdy"));

            // Header: [magic (4)][threshold (1)][nonce (24)]
            let mut output_file = fs::File::create(&output_path)
                .map_err(|_| MainError::InvalidInput("Invalid Path: Output".to_string()))?;

            output_file
                .write_all(MAGIC)
                .map_err(|e| MainError::InternalError(format!("Failed to write magic: {e}")))?;
            output_file
                .write_all(&[min_shares.get()])
                .map_err(|e| MainError::InternalError(format!("Failed to write threshold: {e}")))?;
            output_file
                .write_all(encrypted.nonce_as_slice())
                .map_err(|e| MainError::InternalError(format!("Failed to write nonce: {e}")))?;
            output_file
                .write_all(encrypted.data_as_slice())
                .map_err(|e| {
                    MainError::InternalError(format!("Failed to write ciphertext: {e}"))
                })?;

            println!("Encryption complete! Splitting shares...");
            write_shares(encrypted.shares(), &share_prefix)?;
        }

        Decrypt { share_prefix } => {
            let shares = get_shares(&share_prefix)?;

            let raw = fs::read(&cli_options.input).map_err(|_| {
                MainError::InternalError("Failed to open provided .shdy file".to_string())
            })?;

            if raw.len() < HEADER_LEN {
                return Err(MainError::InvalidInput(
                    "File too short to contain a valid header.".to_string(),
                ));
            }

            if &raw[0..MAGIC_LEN] != MAGIC {
                return Err(MainError::InvalidInput(
                    "File does not have the shdy magic bytes; is this a .shdy file?".to_string(),
                ));
            }

            let threshold_byte = raw[MAGIC_LEN];
            let threshold = NonZero::<u8>::new(threshold_byte).ok_or_else(|| {
                MainError::InvalidInput(
                    "Threshold in file header is zero; corrupt file.".to_string(),
                )
            })?;

            let nonce: &[u8; 24] = raw[MAGIC_LEN + THRESHOLD_LEN..HEADER_LEN]
                .try_into()
                .expect("slice is exactly NONCE_LEN bytes");

            let ciphertext = &raw[HEADER_LEN..];

            let plaintext =
                decrypt_bytes(ciphertext, threshold, &shares, nonce).map_err(|e| match e {
                    shardlib::Error::Shamir(s) => match s {
                        ShamirError::TooFewShares(n) => {
                            MainError::InvalidInput(format!("Too few shares. Need: {n}"))
                        }
                        ShamirError::DuplicateShares => {
                            MainError::InvalidInput("Duplicate shares provided.".to_string())
                        }
                        ShamirError::ModError => {
                            MainError::InternalError("Shamir modulus error.".to_string())
                        }
                        ShamirError::KeyExtraction => {
                            MainError::InternalError("Key extraction failed.".to_string())
                        }
                    },
                    shardlib::Error::DecryptionError => MainError::InvalidInput(
                        "Decryption failed; wrong shares or corrupt file.".to_string(),
                    ),
                    shardlib::Error::ObviousContradiction => {
                        MainError::InternalError("Contradiction during decryption.".to_string())
                    }
                    shardlib::Error::EncryptionError => {
                        MainError::InternalError("Unexpected encryption error.".to_string())
                    }
                })?;

            let output_path = cli_options
                .output
                .unwrap_or_else(|| cli_options.input.with_extension(""));

            fs::write(&output_path, &plaintext)
                .map_err(|e| MainError::InternalError(format!("Failed to write output: {e}")))?;

            println!("Decryption complete!");
        }
    }

    Ok(())
}
