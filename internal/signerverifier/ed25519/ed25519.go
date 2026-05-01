// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package ed25519

import (
	"crypto"
	goed25519 "crypto/ed25519"
	"encoding/base64"
	"fmt"

	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
)

// SignerVerifier implements common.SignerVerifier for Ed25519 keys.
type SignerVerifier struct {
	private goed25519.PrivateKey
	public  goed25519.PublicKey
	keyID   string
	ssKey   *common.SSLibKey
}

// New creates an Ed25519 SignerVerifier from a private key.
func New(privKey goed25519.PrivateKey) (*SignerVerifier, error) {
	pub := privKey.Public().(goed25519.PublicKey)
	return fromPublicKey(pub, privKey)
}

// NewVerifier creates a verify-only SignerVerifier from a public key.
func NewVerifier(pubKey goed25519.PublicKey) (*SignerVerifier, error) {
	return fromPublicKey(pubKey, nil)
}

// NewVerifierFromSSLibKey creates a verifier from an SSLibKey.
func NewVerifierFromSSLibKey(key *common.SSLibKey) (*SignerVerifier, error) {
	pubBytes, err := base64.StdEncoding.DecodeString(key.KeyVal.Public)
	if err != nil {
		return nil, fmt.Errorf("decoding ed25519 public key: %w", err)
	}
	if len(pubBytes) != goed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key length %d", len(pubBytes))
	}
	return fromPublicKey(goed25519.PublicKey(pubBytes), nil)
}

// NewFromCryptoPublicKey creates a verifier from a crypto.PublicKey.
func NewFromCryptoPublicKey(pub crypto.PublicKey) (*SignerVerifier, error) {
	ed25519Pub, ok := pub.(goed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519 (got %T)", pub)
	}
	return fromPublicKey(ed25519Pub, nil)
}

func fromPublicKey(pub goed25519.PublicKey, priv goed25519.PrivateKey) (*SignerVerifier, error) {
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	keyID, err := common.ComputeKeyID(common.ED25519KeyType, common.ED25519SigningScheme, pubB64)
	if err != nil {
		return nil, err
	}
	ssKey := &common.SSLibKey{
		KeyID:   keyID,
		KeyType: common.ED25519KeyType,
		Scheme:  common.ED25519SigningScheme,
		KeyVal:  common.KeyVal{Public: pubB64},
	}
	return &SignerVerifier{
		private: priv,
		public:  pub,
		keyID:   keyID,
		ssKey:   ssKey,
	}, nil
}

func (s *SignerVerifier) Sign(data []byte) ([]byte, error) {
	if s.private == nil {
		return nil, common.ErrNoPrivateKey
	}
	return goed25519.Sign(s.private, data), nil
}

func (s *SignerVerifier) Verify(data, sig []byte) error {
	if !goed25519.Verify(s.public, data, sig) {
		return fmt.Errorf("%w: ed25519 signature invalid", common.ErrVerificationFailed)
	}
	return nil
}

func (s *SignerVerifier) KeyID() string            { return s.keyID }
func (s *SignerVerifier) Public() *common.SSLibKey { return s.ssKey }
