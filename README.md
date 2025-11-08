# aafkeygen

AAFKeygen — Authenticated Access File encryptor for Linux

Version: 1.4.4

AAFKeygen is a small command-line utility for encrypting files with a password-derived key. It now supports authenticated encryption (AES-256-GCM) and a versioned on-disk header so encrypted files can include metadata (KDF, salt, iterations, AEAD id, IV length, original filename, timestamp).

Quick usage

- Encrypt a file (default AEAD/GCM):

```sh
./aafkeygen -E secret.txt -p hunter2
```

- Encrypt and force AES-GCM explicitly:

```sh
./aafkeygen -E secret.txt -p hunter2 --aead gcm
```

- Override PBKDF2 iterations (default 100000):

```sh
./aafkeygen -E secret.txt -p hunter2 --iterations 200000
```

- Inspect a .aaf file header (shows KDF, salt, iterations, AEAD, IV length, original filename):

```sh
./aafkeygen --inspect secret.txt.aaf
```

Notes for users / migration

- Files produced with v1.4.4 use the AAF4 header format (version 2) that includes PBKDF2 salt and iterations plus AEAD metadata. Older versions (AAFv1) are still readable by the tool.
- If you rely on the old (CBC) behavior, use the `--legacy` flag when encrypting to force the legacy KDF/behavior.

License

See the `LICENSE` file in this repository.
