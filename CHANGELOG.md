# Changelog

All notable changes to this project will be documented in this file.


## [0.2.0] - 2025-04-26
### Added
- New `EncryptBytesWithKey([]byte, []byte)` function to encrypt data and return ciphertext bytes.
- New `EncryptBase64WithKey([]byte, []byte)` function to encrypt data and return ciphertext as a base64-encoded string.
- New `DecryptBytesWithKey([]byte, []byte)` function to decrypt raw ciphertext bytes.
- New `DecryptBase64WithKey(string, []byte)` function to decrypt base64-encoded ciphertext.
- Full support for handling encryption and decryption directly with `[]byte` instead of `string`.

### Changed
- `EncryptWithKey` and `DecryptWithKey` have been refactored into clearer and more explicit functions.
- Improved consistency and clarity across `xsecrets` encryption utilities.

### Removed
- Deprecated interfaces like `EncryptWithKey([]byte, []byte) (string, error)` have been replaced by new, more structured functions.

---

## [0.1.0] - 2025-04-15
### Added
- Initial release of `xencryptor` with:
  - PEM RSA key generation
  - AES-GCM encryption and decryption of RSA private keys
  - CLI tool integration
