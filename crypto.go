package canoe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"hash"
	"io"
	"strings"

	bg "github.com/SSSOCPaulCote/blunderguard"
	e "github.com/pkg/errors"
)

const (
	ErrNoKeyFound        = bg.Error("no key found")
	ErrPassphraseMissing = bg.Error("this private key is passphrase protected")
	ErrNotEncryptedKey   = bg.Error("not an encrypted key")
	ErrUnsupportedKey    = bg.Error("unsupported key type")
)

func encryptedBlock(block *pem.Block) bool {
	return strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED")
}

// ParsePrivateKey returns a private key from a PEM encoded private key.
// It only supports RSA. If the private key is encrypted, it will return an error
func ParsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrNoKeyFound
	}

	if encryptedBlock(block) {
		return nil, ErrPassphraseMissing
	}
	if block.Type != "RSA PRIVATE KEY" && block.Type != "BEGIN PRIVATE KEY" {
		return nil, ErrUnsupportedKey
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// ParsePrivateKeyWithPassphrase returns an RSA private key from a PEM encoded private
// key and passphrase.
func ParsePrivateKeyWithPassphrase(pemBytes []byte, passphrase []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrNoKeyFound
	}

	if !encryptedBlock(block) || !x509.IsEncryptedPEMBlock(block) {
		return nil, ErrNotEncryptedKey
	}
	buf, err := x509.DecryptPEMBlock(block, passphrase)
	if err != nil {
		if err == x509.IncorrectPasswordError {
			return nil, err
		}
		return nil, e.Wrap(err, "cannot decode encrypted private key")
	}

	if block.Type != "RSA PRIVATE KEY" && block.Type != "BEGIN PRIVATE KEY" {
		return nil, ErrUnsupportedKey
	}
	return x509.ParsePKCS1PrivateKey(buf)
}

// ParsePublicKey will take a pem encoded RSA Public key and parse it
func ParsePublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrNoKeyFound
	}
	// if block.Type != "RSA PUBLIC KEY" {
	// 	return nil, ErrUnsupportedKey
	// }
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, ErrUnsupportedKey
	}
	return rsaKey, nil
}

// DecryptAESGCM will take ciphered data in bytes and an encryption key in bytes and decrypt the data using AES-GCM techniques
func DecryptAESGCM(encryptedBytes, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	gcmInstance, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}
	nonce, cipheredData := encryptedBytes[:gcmInstance.NonceSize()], encryptedBytes[gcmInstance.NonceSize():]
	return gcmInstance.Open(nil, nonce, cipheredData, nil)
}

// EncryptAESGCM takes raw bytes and an encryption key and encrypts the data using AES-GCM techniques
func EncryptAESGCM(rawBytes, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	gcmInstance, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}
	nonce := make([]byte, gcmInstance.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return []byte{}, err
	}
	encryptedBytes := gcmInstance.Seal(nonce, nonce, rawBytes, nil)
	return encryptedBytes, nil
}

// CreateAESKey creates a 256 bit encryption key
func CreateAESKey() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key[:]
}

// EncryptOAEP is a wrapper function over the crypto/rsa package function of the same name
// It divides longer messages into chunks
func EncryptOAEP(hash hash.Hash, random io.Reader, public *rsa.PublicKey, msg, label []byte) ([]byte, error) {
	msgLen := len(msg)
	step := public.Size() - 2*hash.Size() - 2
	var encryptedBytes []byte
	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		encryptedBlockBytes, err := rsa.EncryptOAEP(hash, random, public, msg[start:finish], label)
		if err != nil {
			return nil, err
		}

		encryptedBytes = append(encryptedBytes, encryptedBlockBytes...)
	}

	return encryptedBytes, nil
}

// DecryptOAEP is a wrapper function over the crypto/rsa package function of the same name
// It reconstructs longer messages from chunks
func DecryptOAEP(hash hash.Hash, random io.Reader, private *rsa.PrivateKey, msg []byte, label []byte) ([]byte, error) {
	msgLen := len(msg)
	step := private.PublicKey.Size()
	var decryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		decryptedBlockBytes, err := rsa.DecryptOAEP(hash, random, private, msg[start:finish], label)
		if err != nil {
			return nil, err
		}

		decryptedBytes = append(decryptedBytes, decryptedBlockBytes...)
	}

	return decryptedBytes, nil
}
