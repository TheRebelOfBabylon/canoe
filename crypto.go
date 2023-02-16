package canoe

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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
func ParsePrivateKey(pemBytes []byte, passphrase []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrNoKeyFound
	}

	if encryptedBlock(block) {
		return nil, ErrPassphraseMissing
	}
	if block.Type != "RSA PRIVATE KEY" {
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

	if block.Type != "RSA PRIVATE KEY" {
		return nil, ErrUnsupportedKey
	}
	return x509.ParsePKCS1PrivateKey(buf)
}
