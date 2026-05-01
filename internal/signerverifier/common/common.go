// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	ErrVerificationFailed = errors.New("signature verification failed")
	ErrNoPrivateKey       = errors.New("no private key available for signing")
)

// SignerVerifier can sign data and verify signatures over it.
type SignerVerifier interface {
	Sign(data []byte) ([]byte, error)
	Verify(data, sig []byte) error
	KeyID() string
	Public() *SSLibKey
}

// SSLibKey represents a signing key in the Secure Systems Library format.
type SSLibKey struct {
	KeyID           string            `json:"keyid"`
	KeyIDHash       []string          `json:"keyid_hash_algorithms,omitempty"`
	KeyType         string            `json:"keytype"`
	KeyVal          KeyVal            `json:"keyval"`
	Scheme          string            `json:"scheme"`
	KeyValThreshold int               `json:"threshold,omitempty"`
	CustomData      map[string]string `json:"custom,omitempty"`
}

// KeyVal holds the public (and optionally private) key material.
type KeyVal struct {
	Public      string `json:"public"`
	Private     string `json:"private,omitempty"`
	Identity    string `json:"identity,omitempty"`
	Issuer      string `json:"issuer,omitempty"`
	Certificate string `json:"certificate,omitempty"`
}

// Supported key types.
const (
	RSAKeyType      = "rsa"
	ED25519KeyType  = "ed25519"
	ECDSAKeyType    = "ecdsa"
	SSHKeyType      = "ssh"
	GPGKeyType      = "gpg"
	SigstoreKeyType = "sigstore"
)

// Supported signing schemes.
const (
	RSASigningScheme     = "rsassa-pss-sha256"
	ED25519SigningScheme = "ed25519"
	ECDSASigningScheme   = "ecdsa-sha2-nistp256"
	SSHSigningScheme     = "ssh"
	GPGSigningScheme     = "pgp"
	FulcioSigningScheme  = "fulcio"
)

// canonicalKeyForID is the minimal struct used to compute reproducible key IDs.
type canonicalKeyForID struct {
	KeyType string            `json:"keytype"`
	KeyVal  map[string]string `json:"keyval"`
	Scheme  string            `json:"scheme"`
}

// ComputeKeyID computes the TUF/SSLib canonical key ID:
//
//	KeyID = hex(SHA256(canonical_JSON({"keytype":…, "keyval":{"public":…}, "scheme":…})))
func ComputeKeyID(keyType, scheme, publicVal string) (string, error) {
	ck := canonicalKeyForID{
		KeyType: keyType,
		KeyVal:  map[string]string{"public": publicVal},
		Scheme:  scheme,
	}
	data, err := json.Marshal(ck)
	if err != nil {
		return "", fmt.Errorf("computing key ID: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
