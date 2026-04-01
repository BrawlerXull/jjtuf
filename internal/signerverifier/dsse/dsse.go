// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package dsse

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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
