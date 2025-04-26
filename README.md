# xencryptor

[![Go Report Card](https://goreportcard.com/badge/github.com/eugene-ruby/xencryptor)](https://goreportcard.com/report/github.com/eugene-ruby/xencryptor) 
[![Build Status](https://github.com/eugene-ruby/xencryptor/actions/workflows/ci.yml/badge.svg)](https://github.com/eugene-ruby/xencryptor/actions)  
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`xencryptor` is a Go library and CLI tool for generating RSA key pairs and securely encrypting/decrypting private keys using AES-GCM with HMAC-SHA256–based key derivation.

## Features

- Generate 4096‑bit RSA key pairs as PEM files
- AES‑GCM encryption & decryption of RSA private keys
- Deterministic key derivation from a master key and label (`DeriveKey`)
- Simple CLI interface for seamless integration in shell pipelines
- Fully tested with Go test suite

## Installation

Install the CLI tool:
```bash
go install github.com/eugene-ruby/xencryptor/cmd/xencryptor@latest
```

Add as a library dependency:
```bash
go get github.com/eugene-ruby/xencryptor/xsecrets
```

## CLI Usage

### Generate a new RSA key pair

```bash
xencryptor -newpem mykey
# Creates mykey.pem and mykey_pub.pem
```

### Encrypt an existing private key

```bash
cat mykey.pem | xencryptor -encrypt pkp \
  -master "YOUR_MASTER_KEY" \
  -label "ENCRYPTION_LABEL" > mykey.enc
```

### Decrypt and verify

```bash
echo "BASE64_CIPHERTEXT" | xencryptor -encrypt pkp \
  -master "YOUR_MASTER_KEY" \
  -label "ENCRYPTION_LABEL"
```

## Library Usage

```go
import (
    "fmt"
    "github.com/eugene-ruby/xencryptor/xsecrets"
)

func main() {
    // Generate PEM files on disk
    if err := xsecrets.GeneratePEMFiles("mykey"); err != nil {
        // handle error
    }

    // Read an existing PEM file into []byte
    pemBytes := []byte("-----BEGIN RSA PRIVATE KEY-----...")

    // Encrypt private RSA key
    cipherText, err := xsecrets.EncryptPrivateRSA(pemBytes, "master-secret", "label")
    if err != nil {
        // handle error
    }
    fmt.Println("Encrypted:", cipherText)

    // Decrypt back to *rsa.PrivateKey
    privKey, err := xsecrets.DecryptPrivateRSA(cipherText, "master-secret", "label")
    if err != nil {
        // handle error
    }
    fmt.Printf("Decrypted Key: %%+v\n", privKey)
}
```

## Symmetric Encryption Functions

| Function | Input | Output | Description |
|:---------|:------|:-------|:------------|
| `EncryptBytesWithKey([]byte, []byte)` | plaintext, key | ciphertext []byte | Encrypts raw bytes, returns ciphertext bytes |
| `EncryptBase64WithKey([]byte, []byte)` | plaintext, key | base64 string | Encrypts bytes and encodes ciphertext as base64 |
| `DecryptBytesWithKey([]byte, []byte)` | ciphertext, key | plaintext []byte | Decrypts ciphertext bytes into plaintext bytes |
| `DecryptBase64WithKey(string, []byte)` | base64 ciphertext, key | plaintext []byte | Decodes base64 and decrypts ciphertext |


## Testing

Run unit tests:
```bash
go test ./xsecrets
```

## Contributing

Contributions are welcome! Please open issues or submit pull requests.  
Remember to follow the Go code style and include tests for new features.

## License

This project is licensed under the [MIT License](/LICENSE)

