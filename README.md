# aafkeygen

AAFKeygen — Authenticated Access File encryptor for Linux


AAFKeygen is a small command-line utility for encrypting files with a password-derived key. It now supports authenticated encryption (AES-256-GCM) and a versioned on-disk header so encrypted files can include metadata (KDF, salt, iterations, AEAD id, IV length, original filename, timestamp).

Quick usage

- Encrypt a file (default AEAD/GCM):

```sh
./aafkeygen -E secret.txt
```

- Encrypt and force AES-GCM explicitly:

```sh
./aafkeygen -E secret.txt --aead gcm
```

- Override PBKDF2 iterations (default 100000):

```sh
./aafkeygen -E secret.txt --iterations 200000
```

- Inspect a .aaf file header (shows KDF, salt, iterations, AEAD, IV length, original filename):
 - Temporary decrypt & open (prompt-based):

```sh
./aafkeygen -D secret.jpg.aaf --temp-decrypt
```

This mode will decrypt the AAF to a secure temporary file (preserving the original filename/extension stored in the AAF header), open it with your system default viewer via `xdg-open`, prompt you to press ENTER when you're done viewing, then re-encrypt the file and attempt to securely delete the plaintext.

Security notes and limitations for `--temp-decrypt` are listed below.

 - Inspect a .aaf file header (shows KDF, salt, iterations, AEAD, IV length, original filename):

```sh
./aafkeygen --inspect secret.txt.aaf
```

Temporary decrypt security notes

- The tool writes the plaintext to a temporary file with permissions 0600 inside `$XDG_RUNTIME_DIR` (if set), otherwise `$TMPDIR` or `/tmp`.
- The program attempts a best-effort overwrite (single-pass zeroing) of the plaintext file before unlinking. This is not a guarantee — filesystems (SSD wear-leveling), copy-on-write, snapshots, or system-level backups can retain plaintext.
- Desktop viewers and the OS may create thumbnails, cache copies, or memory-resident copies that the tool cannot control. Avoid using `--temp-decrypt` on untrusted or multi-user systems if you need strong guarantees.
- For maximum safety consider decrypting on removable media or an isolated machine and prefer full-disk encryption.

If you want automated detection of when the viewer closes (instead of the user pressing ENTER), we can add an optional `--wait-method=lsof` mode that uses `lsof` to detect open file handles; that requires `lsof` to be available and may be less portable.

License

See the `LICENSE` file in this repository.
