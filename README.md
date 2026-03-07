# Shardy

The best mass encryption tool for servers.

## Features

* Fully headless. Can be scripted however you want.
* Extremely flexible, thanks to configuration via flags.
* Portable, as it requires no config.

## Primitives

* Encryption is based off tried and tested stream cipher ChaCha20, specifically XChaCha20-Poly1305
* Uses Shamir's Secret Sharing to split keyfiles, allowing you to distribute them and not have a single point of failure
* Uses random keyfiles for encryption to ensure security, avoiding human input entirely.
* Uses BLAKE3 to hash the keyfile, a well respected hasher known for speed while being secure.
