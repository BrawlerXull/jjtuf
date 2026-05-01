// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package ecdsa

import (
	"crypto"
	gecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
)

type ecdsaSig struct {
	R, S *big.Int
}

// SignerVerifier implements common.SignerVerifier for ECDSA P-256 keys.
type SignerVerifier struct {
	private *gecdsa.PrivateKey
	public  *gecdsa.PublicKey
	keyID   string
	ssKey   *common.SSLibKey
}

// New creates an ECDSA SignerVerifier from a private key.
func New(privKey *gecdsa.PrivateKey) (*SignerVerifier, error) {
	return fromPublicKey(&privKey.PublicKey, privKey)
}

// NewVerifier creates a verify-only ECDSA SignerVerifier.
func NewVerifier(pubKey *gecdsa.PublicKey) (*SignerVerifier, error) {
	return fromPublicKey(pubKey, nil)
}

// NewVerifierFromSSLibKey creates a verifier from an SSLibKey.
func NewVerifierFromSSLibKey(key *common.SSLibKey) (*SignerVerifier, error) {
	pubBytes, err := base64.StdEncoding.DecodeString(key.KeyVal.Public)
	if err != nil {
		return nil, fmt.Errorf("decoding ecdsa public key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing ecdsa public key: %w", err)
	}
	ecPub, ok := pub.(*gecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ecdsa public key")
	}
	return fromPublicKey(ecPub, nil)
}

// NewFromCryptoPublicKey creates a verifier from a crypto.PublicKey.
func NewFromCryptoPublicKey(pub crypto.PublicKey) (*SignerVerifier, error) {
	ecPub, ok := pub.(*gecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not ECDSA (got %T)", pub)
	}
	return fromPublicKey(ecPub, nil)
}

func fromPublicKey(pub *gecdsa.PublicKey, priv *gecdsa.PrivateKey) (*SignerVerifier, error) {
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("only P-256 curve is supported (got %s)", pub.Curve.Params().Name)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshaling ecdsa public key: %w", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pubDER)
	keyID, err := common.ComputeKeyID(common.ECDSAKeyType, common.ECDSASigningScheme, pubB64)
	if err != nil {
		return nil, err
	}
	ssKey := &common.SSLibKey{
		KeyID:   keyID,
		KeyType: common.ECDSAKeyType,
		Scheme:  common.ECDSASigningScheme,
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
	r, sv, err := gecdsa.Sign(rand.Reader, s.private, h[:])
	if err != nil {
		return nil, fmt.Errorf("ecdsa signing: %w", err)
	}
	encoded, err := asn1.Marshal(ecdsaSig{R: r, S: sv})
	if err != nil {
		return nil, fmt.Errorf("encoding ecdsa signature: %w", err)
	}
	return encoded, nil
}

func (s *SignerVerifier) Verify(data, sig []byte) error {
	h := sha256.Sum256(data)
	var parsed ecdsaSig
	if _, err := asn1.Unmarshal(sig, &parsed); err != nil {
		return fmt.Errorf("%w: parsing ecdsa signature: %v", common.ErrVerificationFailed, err)
	}
	if !gecdsa.Verify(s.public, h[:], parsed.R, parsed.S) {
		return fmt.Errorf("%w: ecdsa signature invalid", common.ErrVerificationFailed)
	}
	return nil
}

func (s *SignerVerifier) KeyID() string            { return s.keyID }
func (s *SignerVerifier) Public() *common.SSLibKey { return s.ssKey }
