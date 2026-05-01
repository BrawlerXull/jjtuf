// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

// Package ssh handles SSH key format parsing for jjtuf.
// It parses OpenSSH private keys and authorized-keys-format public keys,
// then delegates signing/verification to the appropriate algorithm package.
package ssh

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"strings"

	gxssh "golang.org/x/crypto/ssh"

	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
	sigecdsa "github.com/jjtuf/jjtuf/internal/signerverifier/ecdsa"
	siged25519 "github.com/jjtuf/jjtuf/internal/signerverifier/ed25519"
	sigrsa "github.com/jjtuf/jjtuf/internal/signerverifier/rsa"
)

// LoadSSLibKeyFromAuthorizedKey parses a single line in authorized_keys format
// (e.g., the contents of ~/.ssh/id_ed25519.pub) and returns an SSLibKey.
func LoadSSLibKeyFromAuthorizedKey(line string) (*common.SSLibKey, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, fmt.Errorf("empty or comment line")
	}

	pub, _, _, _, err := gxssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("parsing authorized key: %w", err)
	}

	return ssLibKeyFromSSHPublicKey(pub)
}

// ssLibKeyFromSSHPublicKey converts an ssh.PublicKey to the underlying
// algorithm's SSLibKey.
func ssLibKeyFromSSHPublicKey(sshPub gxssh.PublicKey) (*common.SSLibKey, error) {
	cryptoPub, ok := sshPub.(gxssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("SSH public key does not implement CryptoPublicKey")
	}

	switch pub := cryptoPub.CryptoPublicKey().(type) {
	case ed25519.PublicKey:
		sv, err := siged25519.NewVerifier(pub)
		if err != nil {
			return nil, err
		}
		return sv.Public(), nil
	case *ecdsa.PublicKey:
		sv, err := sigecdsa.NewVerifier(pub)
		if err != nil {
			return nil, err
		}
		return sv.Public(), nil
	case *rsa.PublicKey:
		sv, err := sigrsa.NewVerifier(pub)
		if err != nil {
			return nil, err
		}
		return sv.Public(), nil
	default:
		return nil, fmt.Errorf("unsupported SSH key algorithm: %T", cryptoPub.CryptoPublicKey())
	}
}

// LoadSignerVerifierFromOpenSSHKey parses an OpenSSH private key (PEM bytes
// beginning with "-----BEGIN OPENSSH PRIVATE KEY-----") and returns a
// SignerVerifier for the underlying algorithm.
func LoadSignerVerifierFromOpenSSHKey(pemData []byte) (common.SignerVerifier, error) {
	rawKey, err := gxssh.ParseRawPrivateKey(pemData)
	if err != nil {
		return nil, fmt.Errorf("parsing OpenSSH private key: %w", err)
	}

	switch k := rawKey.(type) {
	case ed25519.PrivateKey:
		return siged25519.New(k)
	case *ed25519.PrivateKey:
		return siged25519.New(*k)
	case *ecdsa.PrivateKey:
		return sigecdsa.New(k)
	case *rsa.PrivateKey:
		return sigrsa.New(k)
	default:
		return nil, fmt.Errorf("unsupported SSH key type: %T", rawKey)
	}
}

// NewVerifierFromSSLibKey creates a verifier for an ssh-typed SSLibKey.
// The public value is expected to be in authorized_keys format.
func NewVerifierFromSSLibKey(key *common.SSLibKey) (common.SignerVerifier, error) {
	ssKey, err := LoadSSLibKeyFromAuthorizedKey(key.KeyVal.Public)
	if err != nil {
		return nil, err
	}

	// Reconstruct the right verifier from the resolved key
	switch ssKey.KeyType {
	case common.ED25519KeyType:
		return siged25519.NewVerifierFromSSLibKey(ssKey)
	case common.ECDSAKeyType:
		return sigecdsa.NewVerifierFromSSLibKey(ssKey)
	case common.RSAKeyType:
		return sigrsa.NewVerifierFromSSLibKey(ssKey)
	default:
		return nil, fmt.Errorf("unsupported key type from SSH key: %s", ssKey.KeyType)
	}
}
