// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package common

// SSLibKey represents a signing key in the Secure Systems Library format.
type SSLibKey struct {
	KeyID       string            `json:"keyid"`
	KeyIDHash   []string          `json:"keyid_hash_algorithms,omitempty"`
	KeyType     string            `json:"keytype"`
	KeyVal      KeyVal            `json:"keyval"`
	Scheme      string            `json:"scheme"`
	KeyValThreshold int           `json:"threshold,omitempty"`
	CustomData  map[string]string `json:"custom,omitempty"`
}

// KeyVal holds the public (and optionally private) key material.
type KeyVal struct {
	Public     string `json:"public"`
	Private    string `json:"private,omitempty"`
	Identity   string `json:"identity,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
	Certificate string `json:"certificate,omitempty"`
}

// Supported key types.
const (
	RSAKeyType     = "rsa"
	ED25519KeyType = "ed25519"
	ECDSAKeyType   = "ecdsa"
	SSHKeyType     = "ssh"
	GPGKeyType     = "gpg"
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
