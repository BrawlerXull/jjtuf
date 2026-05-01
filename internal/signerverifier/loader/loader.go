// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

// Package loader provides unified key loading for jjtuf.
// It detects PEM block types and SSH authorized-key formats and delegates to
// the appropriate algorithm-specific package.
package loader

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
	sigecdsa "github.com/jjtuf/jjtuf/internal/signerverifier/ecdsa"
	siged25519 "github.com/jjtuf/jjtuf/internal/signerverifier/ed25519"
	sigrsa "github.com/jjtuf/jjtuf/internal/signerverifier/rsa"
	sigsigstore "github.com/jjtuf/jjtuf/internal/signerverifier/sigstore"
	sigssh "github.com/jjtuf/jjtuf/internal/signerverifier/ssh"
)

// LoadSignerVerifierFromFile loads a private key from the file at path.
// Supported formats: PKCS#8 PEM ("PRIVATE KEY"), SEC1 PEM ("EC PRIVATE KEY"),
// PKCS#1 PEM ("RSA PRIVATE KEY"), and OpenSSH PEM ("OPENSSH PRIVATE KEY").
func LoadSignerVerifierFromFile(path string) (common.SignerVerifier, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file %q: %w", path, err)
	}
	return LoadSignerVerifierFromPEM(data)
}

// LoadSignerVerifierFromPEM loads a private key from PEM bytes.
func LoadSignerVerifierFromPEM(pemData []byte) (common.SignerVerifier, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM block found in key data")
	}

	switch block.Type {
	case "PRIVATE KEY": // PKCS#8 — can wrap ed25519, ecdsa, rsa
		raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS#8 private key: %w", err)
		}
		return newFromCryptoKey(raw)

	case "EC PRIVATE KEY": // SEC1
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing EC private key: %w", err)
		}
		return sigecdsa.New(key)

	case "RSA PRIVATE KEY": // PKCS#1
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing RSA private key: %w", err)
		}
		return sigrsa.New(key)

	case "OPENSSH PRIVATE KEY":
		return sigssh.LoadSignerVerifierFromOpenSSHKey(pemData)

	default:
		return nil, fmt.Errorf("unsupported PEM block type: %q", block.Type)
	}
}

// LoadSSLibKeyFromPublicKeyFile loads a public key from the file at path.
// Supported formats:
//   - SSH authorized_keys format (e.g. ~/.ssh/id_ed25519.pub)
//   - PEM "PUBLIC KEY" (PKIX/SPKI)
func LoadSSLibKeyFromPublicKeyFile(path string) (*common.SSLibKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading public key file %q: %w", path, err)
	}
	return LoadSSLibKeyFromPublicKeyBytes(data)
}

// LoadSSLibKeyFromPublicKeyBytes parses a public key from bytes.
func LoadSSLibKeyFromPublicKeyBytes(data []byte) (*common.SSLibKey, error) {
	s := strings.TrimSpace(string(data))

	// PEM-encoded public key
	if strings.HasPrefix(s, "-----BEGIN") {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, errors.New("invalid PEM data")
		}
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("expected PEM type \"PUBLIC KEY\", got %q", block.Type)
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKIX public key: %w", err)
		}
		return ssLibKeyFromCryptoPublicKey(pub)
	}

	// SSH authorized_keys format
	return sigssh.LoadSSLibKeyFromAuthorizedKey(s)
}

// LoadVerifierFromSSLibKey creates a verify-only SignerVerifier from an SSLibKey.
func LoadVerifierFromSSLibKey(key *common.SSLibKey) (common.SignerVerifier, error) {
	switch key.KeyType {
	case common.ED25519KeyType:
		return siged25519.NewVerifierFromSSLibKey(key)
	case common.ECDSAKeyType:
		return sigecdsa.NewVerifierFromSSLibKey(key)
	case common.RSAKeyType:
		return sigrsa.NewVerifierFromSSLibKey(key)
	case common.SSHKeyType:
		return sigssh.NewVerifierFromSSLibKey(key)
	case common.SigstoreKeyType:
		return sigsigstore.NewVerifierFromSSLibKey(key)
	default:
		return nil, fmt.Errorf("unsupported key type for verification: %q", key.KeyType)
	}
}

// newFromCryptoKey dispatches to the algorithm-specific constructor.
func newFromCryptoKey(key interface{}) (common.SignerVerifier, error) {
	switch k := key.(type) {
	case ed25519.PrivateKey:
		return siged25519.New(k)
	case *ecdsa.PrivateKey:
		return sigecdsa.New(k)
	case *rsa.PrivateKey:
		return sigrsa.New(k)
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", key)
	}
}

// ssLibKeyFromCryptoPublicKey converts a crypto.PublicKey to an SSLibKey.
func ssLibKeyFromCryptoPublicKey(pub interface{}) (*common.SSLibKey, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		sv, err := siged25519.NewVerifier(k)
		if err != nil {
			return nil, err
		}
		return sv.Public(), nil
	case *ecdsa.PublicKey:
		sv, err := sigecdsa.NewVerifier(k)
		if err != nil {
			return nil, err
		}
		return sv.Public(), nil
	case *rsa.PublicKey:
		sv, err := sigrsa.NewVerifier(k)
		if err != nil {
			return nil, err
		}
		return sv.Public(), nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
}
