# `.greg` format version 1

All integers are unsigned and stored in network byte order (big endian). Offsets are
in bytes from the beginning of the file.

| Offset | Size | Meaning |
|---:|---:|---|
| 0 | 4 | Magic ASCII `GREG` |
| 4 | 1 | Format version (`1`) |
| 5 | 1 | KDF identifier (`1` = Argon2id) |
| 6 | 1 | Cipher identifier (`1` = AES-256-GCM) |
| 7 | 1 | Flags (must be zero) |
| 8 | 4 | Argon2 time cost |
| 12 | 4 | Argon2 memory cost in KiB |
| 16 | 4 | Argon2 parallelism |
| 20 | 2 | Salt length (version 1 requires 16) |
| 22 | 2 | Nonce length (version 1 requires 12) |
| 24 | 8 | Ciphertext length, including the 16-byte GCM tag |
| 32 | variable | Random Argon2 salt |
| next | variable | Random AES-GCM nonce |
| next | variable | Ciphertext and GCM authentication tag |

The 32-byte fixed header followed by the salt and nonce is AES-GCM associated data.
Consequently, changing any public algorithm, cost, length, salt, or nonce field causes
authentication to fail.

Argon2id version 19 derives a 32-byte AES key from the UTF-8 password and stored salt.
The default costs are three iterations, 65,536 KiB of memory, and four lanes. Readers
validate cost parameters before deriving a key to limit malicious resource requests.

## Plaintext payload before encryption

The authenticated plaintext begins with a four-byte big-endian JSON length, followed
by that many bytes of UTF-8 JSON, followed by the unmodified original file bytes.
The JSON object has these members:

```json
{
  "extension": ".xlsx",
  "filename": "finances.xlsx",
  "metadata": {}
}
```

The JSON is wholly encrypted. A reader rejects absolute names, path components,
separator characters, inconsistent extensions, malformed metadata, extra container
bytes, unsupported versions/algorithms, and inconsistent lengths.

Save and Lock currently retains the original salt and in-memory derived key for that
unlocked session, but generates a new random nonce. Creating a new `.greg` always
generates both a new random salt and nonce. A future password-change operation can
decrypt in memory and create a replacement with a new salt, key, and nonce.
