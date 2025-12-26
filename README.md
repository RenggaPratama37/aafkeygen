# aafkeygen

AAFKeygen — Authenticated Access File encryptor for Linux


AAFKeygen is a small command-line utility for encrypting files with a password-derived key. It now supports authenticated encryption (AES-256-GCM) and a versioned on-disk header so encrypted files can include metadata (KDF, salt, iterations, AEAD id, IV length, original filename, timestamp).
AAFKeygen is a small command-line utility for encrypting files with a password-derived key. It supports authenticated encryption (AES-256-GCM), a versioned on-disk header, and optional pre-encryption compression.

Highlights
- Authenticated encryption: AES-256-GCM (primary) with AES-CBC fallback where needed
- Password-based key derivation: PBKDF2-HMAC-SHA256 (iterations configurable)
- Versioned AAF4 header (stores KDF metadata, salt, iterations, AEAD id, IV, original filename, timestamp)
- Optional gzip compression before encryption (`--compress`)
- `--temp-decrypt` helper: decrypt to a secure temp file, open with viewer, re-encrypt after close

Quick usage

- Encrypt a file (default AEAD/GCM):

```sh
./aafkeygen -E secret.txt
```

- Encrypt with gzip compression before encryption (saves space, header notes compression):

```sh
./aafkeygen -E secret.txt --compress -o secret.txt.aaf
```

- Decrypt a file (restore original filename if present in header):

```sh
./aafkeygen -D secret.txt.aaf
```

- Temp-decrypt and open with your desktop viewer (prompt-based):

```sh
./aafkeygen -D secret.jpg.aaf --temp-decrypt
```

- Inspect header metadata (shows KDF, salt, iterations, AEAD, IV length, compression, original filename):

```sh
./aafkeygen --inspect secret.txt.aaf
```

Build & install (generic Linux)

Install build dependencies (Debian/Ubuntu example):

```sh
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev zlib1g-dev pkg-config
```

Build and install locally:

```sh
make
sudo make install
```

Notes for packagers / CI
- The project links with OpenSSL and zlib. Ensure `libssl-dev` and `zlib1g-dev` (or equivalent) are present in the build environment for each target architecture.

Compatibility and migration notes

- This release uses AAF4 header format version 2 for new files. The header stores a `comp_id` field (0 = none, 1 = gzip) when `--compress` is used.
- The tool intentionally rejects legacy/older formats (users should re-encrypt with older tools to migrate files before upgrading). `--inspect` can be used to view header metadata before deciding how to proceed.
- Decryption prefers the original filename stored in the header; if that field is absent the tool falls back to trimming the `.aaf` extension from the input filename.

Security notes

- `--temp-decrypt` writes plaintext to a temporary file with restrictive permissions (0600) and attempts best-effort cleanup, but this is not a guarantee against residual copies (SSD wear-leveling, OS caches, thumbnails, backups).
- Use `--temp-decrypt` only on machines you trust and consider full-disk encryption and removable media for high-assurance workflows.

Testing

- Create a small file and run a compressed encrypt / decrypt roundtrip to verify behavior:

```sh
echo "hello" > test.txt
./aafkeygen -E test.txt --compress -o test.aaf --keep
./aafkeygen --inspect test.aaf
./aafkeygen -D test.aaf -o restored.txt
diff test.txt restored.txt
```

If `diff` reports no differences the roundtrip is successful.

License

See the `LICENSE` file in this repository.
