# xencryptor

[![Go Report Card](https://goreportcard.com/badge/github.com/eugene-ruby/xencryptor)](https://goreportcard.com/report/github.com/eugene-ruby/xencryptor)  
[![Build Status](https://github.com/eugene-ruby/xencryptor/actions/workflows/ci.yml/badge.svg)](https://github.com/eugene-ruby/xencryptor/actions)  
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**`xencryptor`** is a Go library and CLI tool for working with RSA and AES encryption.  
It supports safe keypair generation, key wrapping, base64 encoding, and fast symmetric encryption — with test coverage and a simple API.

---

## 🚀 Features

- 🔐 Generate 4096-bit RSA key pairs (as PEM files or in-memory `[]byte`)
- 🔑 Encrypt & decrypt RSA private keys using AES-GCM
- 📦 Symmetric encryption using AES-GCM with optional base64 output
- 🔁 RSA encryption & decryption over `[]byte` (ideal for Redis/protobuf)
- 🎯 Deterministic key derivation via HMAC-SHA256 (`DeriveKey`)
- 🧰 Simple CLI tool for encryption workflows
- ✅ Fully tested with Go test suite

---

## 📦 Installation

Install CLI tool:

```bash
go install github.com/eugene-ruby/xencryptor/cmd/xencryptor@latest
````

Add as a library dependency:

```bash
go get github.com/eugene-ruby/xencryptor/xsecrets
```

---

## 🛠 CLI Usage

### 🔑 Generate a new RSA key pair

```bash
xencryptor -newpem mykey
# Creates mykey.pem and mykey_pub.pem
```

### 🔒 Encrypt private RSA key

```bash
cat mykey.pem | xencryptor -encrypt pkp \
  -master "MY_MASTER_KEY" \
  -label "LABEL" > mykey.enc
```

### 🔓 Decrypt private RSA key

```bash
cat mykey.enc | xencryptor -encrypt pkp \
  -master "MY_MASTER_KEY" \
  -label "LABEL"
```

---

## 📚 Library Usage

### 🔐 Generate & Encrypt Keys

```go
privPEM, pubPEM, _ := xsecrets.GenerateKeyPair()

cipher, _ := xsecrets.EncryptPrivateRSA(privPEM, "master", "label")
privKey, _ := xsecrets.DecryptPrivateRSA(cipher, "master", "label")
```

### 🔁 Symmetric Encryption (AES-GCM)

```go
key := xsecrets.DeriveKey([]byte("master"), "payload")
cipher, _ := xsecrets.EncryptBase64WithKey([]byte("data"), key)
plain, _ := xsecrets.DecryptBase64WithKey(cipher, key)
```

### 🔑 Asymmetric Encryption (RSA)

```go
encrypted, _ := xsecrets.RSAEncryptBytes(pubKey, []byte("secret"))
decrypted, _ := xsecrets.RSADecryptBytes(encrypted, privKey)
```

---

## 🔧 API Overview

### 🔒 Symmetric AES-GCM

| Function                                          | Description                        |
| ------------------------------------------------- | ---------------------------------- |
| `EncryptBytesWithKey([]byte, []byte)` → `[]byte`  | Raw AES encryption                 |
| `EncryptBase64WithKey([]byte, []byte)` → `string` | AES + base64 encoding              |
| `DecryptBytesWithKey([]byte, []byte)` → `[]byte`  | Decrypt raw ciphertext             |
| `DecryptBase64WithKey(string, []byte)` → `[]byte` | Decode + decrypt base64 ciphertext |

### 🔑 Asymmetric RSA (OAEP)

| Function                                              | Description              |
| ----------------------------------------------------- | ------------------------ |
| `RSAEncryptBytes(*rsa.PublicKey, []byte)` → `[]byte`  | Encrypt with public key  |
| `RSADecryptBytes([]byte, *rsa.PrivateKey)` → `[]byte` | Decrypt with private key |

### 🧰 RSA Key Handling

| Function                                   | Description                         |
| ------------------------------------------ | ----------------------------------- |
| `GenerateKeyPair()` → `[]byte` PEM         | In-memory RSA keypair               |
| `GeneratePEMFiles(name)`                   | Save keypair to disk                |
| `EncryptPrivateRSA(pem, master, label)`    | AES-encrypts private PEM            |
| `DecryptPrivateRSA(cipher, master, label)` | AES-decrypts to `*rsa.PrivateKey`   |
| `DeriveKey(master, label)` → `[32]byte`    | HMAC-SHA256 based deterministic KDF |

---

## 🧪 Testing

Run unit tests:

```bash
go test ./xsecrets
```

---

## 🤝 Contributing

Issues and PRs are welcome!
Please include tests for new features and follow idiomatic Go code style.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE)
