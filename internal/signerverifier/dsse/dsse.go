// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package dsse

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
)

var (
	ErrNoSignatures       = errors.New("DSSE envelope has no signatures")
	ErrInvalidPayloadType = errors.New("DSSE envelope has unexpected payload type")
)

// Envelope represents a DSSE (Dead Simple Signing Envelope).
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"` // Base64-encoded
	Signatures  []Signature `json:"signatures"`
}

// Signature represents a single signature in a DSSE envelope.
type Signature struct {
	KeyID     string            `json:"keyid"`
	Sig       string            `json:"sig"` // Base64-encoded
	Extension map[string]string `json:"extension,omitempty"`
}

// NewEnvelope creates a new DSSE envelope with the given payload.
func NewEnvelope(payloadType string, payload []byte) *Envelope {
	return &Envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []Signature{},
	}
}

// DecodePayload returns the decoded payload bytes.
func (e *Envelope) DecodePayload() ([]byte, error) {
	return base64.StdEncoding.DecodeString(e.Payload)
}

// AddSignature adds a signature to the envelope.
func (e *Envelope) AddSignature(keyID string, sig []byte) {
	e.Signatures = append(e.Signatures, Signature{
		KeyID: keyID,
		Sig:   base64.StdEncoding.EncodeToString(sig),
	})
}

// GetSignerKeyIDs returns all key IDs that have signed this envelope.
func (e *Envelope) GetSignerKeyIDs() []string {
	keyIDs := make([]string, 0, len(e.Signatures))
	for _, sig := range e.Signatures {
		keyIDs = append(keyIDs, sig.KeyID)
	}
	return keyIDs
}

// Marshal serializes the envelope to JSON.
func (e *Envelope) Marshal() ([]byte, error) {
	return json.Marshal(e)
}

// Unmarshal deserializes a DSSE envelope from JSON.
func Unmarshal(data []byte) (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

// PAE computes the Pre-Authentication Encoding for DSSE signing.
// PAE(payloadType, payload) = "DSSEv1" + SP + LEN(payloadType) + SP +
// payloadType + SP + LEN(payload) + SP + payload
func PAE(payloadType string, payload []byte) []byte {
	prefix := "DSSEv1"
	result := []byte(prefix)
	result = append(result, ' ')
	result = append(result, []byte(itoa(len(payloadType)))...)
	result = append(result, ' ')
	result = append(result, []byte(payloadType)...)
	result = append(result, ' ')
	result = append(result, []byte(itoa(len(payload)))...)
	result = append(result, ' ')
	result = append(result, payload...)
	return result
}

// Sign signs the envelope using the given signer. The signature is computed
// over PAE(payloadType, rawPayload) and appended to the envelope's Signatures
// slice. It is safe to call Sign multiple times with different signers.
func (e *Envelope) Sign(signer common.SignerVerifier) error {
	rawPayload, err := e.DecodePayload()
	if err != nil {
		return fmt.Errorf("decoding payload for signing: %w", err)
	}
	pae := PAE(e.PayloadType, rawPayload)
	sig, err := signer.Sign(pae)
	if err != nil {
		return fmt.Errorf("signing envelope: %w", err)
	}
	e.AddSignature(signer.KeyID(), sig)
	return nil
}

// VerifySignatures verifies every signature in the envelope against the
// provided set of public keys. It returns the key IDs whose signatures are
// cryptographically valid. Invalid signatures are silently skipped — callers
// that need a threshold check should compare len(return value) to the
// threshold themselves. At least one valid signature is required; an error is
// returned if the envelope has no signatures or none of them verify.
func (e *Envelope) VerifySignatures(keys []*common.SSLibKey, loaders ...VerifierLoader) ([]string, error) {
	if len(e.Signatures) == 0 {
		return nil, ErrNoSignatures
	}

	rawPayload, err := e.DecodePayload()
	if err != nil {
		return nil, fmt.Errorf("decoding payload for verification: %w", err)
	}
	pae := PAE(e.PayloadType, rawPayload)

	// Build an index from key ID → key for O(1) lookup.
	keyByID := make(map[string]*common.SSLibKey, len(keys))
	for _, k := range keys {
		keyByID[k.KeyID] = k
	}

	var validKeyIDs []string
	for _, sig := range e.Signatures {
		key, ok := keyByID[sig.KeyID]
		if !ok {
			continue // signature from unknown key, skip
		}

		var loader VerifierLoader = defaultLoader
		if len(loaders) > 0 && loaders[0] != nil {
			loader = loaders[0]
		}
		verifier, err := loader(key)
		if err != nil {
			continue // can't construct verifier, skip
		}

		sigBytes, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil {
			continue
		}

		if err := verifier.Verify(pae, sigBytes); err == nil {
			validKeyIDs = append(validKeyIDs, sig.KeyID)
		}
	}

	if len(validKeyIDs) == 0 {
		return nil, fmt.Errorf("%w: no valid signatures found in envelope", common.ErrVerificationFailed)
	}
	return validKeyIDs, nil
}

// VerifierLoader is a function that produces a SignerVerifier from a key.
// Callers can inject their own loader for testing; production code should use
// the default (which delegates to the loader package).
type VerifierLoader func(key *common.SSLibKey) (common.SignerVerifier, error)

// defaultLoader is set via SetDefaultLoader to break the import cycle between
// dsse and loader. Call SetDefaultLoader once at program startup.
var defaultLoader VerifierLoader = func(key *common.SSLibKey) (common.SignerVerifier, error) {
	return nil, fmt.Errorf("no default verifier loader configured; call dsse.SetDefaultLoader first")
}

// SetDefaultLoader registers the production verifier loader. Call this once,
// early in main() or in an init() of the cmd package:
//
//	dsse.SetDefaultLoader(loader.LoadVerifierFromSSLibKey)
func SetDefaultLoader(fn VerifierLoader) {
	defaultLoader = fn
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := make([]byte, 0, 10)
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
