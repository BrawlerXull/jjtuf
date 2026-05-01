// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package rsa

import (
	"crypto"
	"crypto/rand"
	gorsa "crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
)

var pssOpts = &gorsa.PSSOptions{
	SaltLength: gorsa.PSSSaltLengthEqualsHash,
	Hash:       crypto.SHA256,
}

// SignerVerifier implements common.SignerVerifier for RSA-PSS-SHA256 keys.
type SignerVerifier struct {
	private *gorsa.PrivateKey
	public  *gorsa.PublicKey
	keyID   string
	ssKey   *common.SSLibKey
}

// New creates an RSA SignerVerifier from a private key.
func New(privKey *gorsa.PrivateKey) (*SignerVerifier, error) {
	return fromPublicKey(&privKey.PublicKey, privKey)
}

// NewVerifier creates a verify-only RSA SignerVerifier.
func NewVerifier(pubKey *gorsa.PublicKey) (*SignerVerifier, error) {
	return fromPublicKey(pubKey, nil)
}

// NewVerifierFromSSLibKey creates a verifier from an SSLibKey.
func NewVerifierFromSSLibKey(key *common.SSLibKey) (*SignerVerifier, error) {
	pubBytes, err := base64.StdEncoding.DecodeString(key.KeyVal.Public)
	if err != nil {
		return nil, fmt.Errorf("decoding rsa public key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing rsa public key: %w", err)
	}
	rsaPub, ok := pub.(*gorsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an rsa public key")
	}
	return fromPublicKey(rsaPub, nil)
}

// NewFromCryptoPublicKey creates a verifier from a crypto.PublicKey.
func NewFromCryptoPublicKey(pub crypto.PublicKey) (*SignerVerifier, error) {
	rsaPub, ok := pub.(*gorsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA (got %T)", pub)
	}
	return fromPublicKey(rsaPub, nil)
}

func fromPublicKey(pub *gorsa.PublicKey, priv *gorsa.PrivateKey) (*SignerVerifier, error) {
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshaling rsa public key: %w", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pubDER)
	keyID, err := common.ComputeKeyID(common.RSAKeyType, common.RSASigningScheme, pubB64)
	if err != nil {
		return nil, err
	}
	ssKey := &common.SSLibKey{
		KeyID:   keyID,
		KeyType: common.RSAKeyType,
		Scheme:  common.RSASigningScheme,
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
	h := sha256.Sum256(data)
	sig, err := gorsa.SignPSS(rand.Reader, s.private, crypto.SHA256, h[:], pssOpts)
	if err != nil {
		return nil, fmt.Errorf("rsa-pss signing: %w", err)
	}
	return sig, nil
}

func (s *SignerVerifier) Verify(data, sig []byte) error {
	h := sha256.Sum256(data)
	if err := gorsa.VerifyPSS(s.public, crypto.SHA256, h[:], sig, pssOpts); err != nil {
		return fmt.Errorf("%w: rsa-pss: %v", common.ErrVerificationFailed, err)
	}
	return nil
}

func (s *SignerVerifier) KeyID() string            { return s.keyID }
func (s *SignerVerifier) Public() *common.SSLibKey { return s.ssKey }
