// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package dsse

import (
	"testing"
)

func TestNewEnvelopeAndDecode(t *testing.T) {
	payload := []byte(`{"key":"value"}`)
	env := NewEnvelope("application/json", payload)

	if env.PayloadType != "application/json" {
		t.Errorf("wrong payload type: %s", env.PayloadType)
	}

	decoded, err := env.DecodePayload()
	if err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if string(decoded) != string(payload) {
		t.Errorf("decoded payload mismatch: got %q, want %q", decoded, payload)
	}
}

func TestAddSignatureAndGetKeyIDs(t *testing.T) {
	env := NewEnvelope("test", []byte("data"))
	env.AddSignature("key1", []byte("sig1"))
	env.AddSignature("key2", []byte("sig2"))

	keyIDs := env.GetSignerKeyIDs()
	if len(keyIDs) != 2 {
		t.Fatalf("expected 2 key IDs, got %d", len(keyIDs))
	}
	if keyIDs[0] != "key1" || keyIDs[1] != "key2" {
		t.Errorf("wrong key IDs: %v", keyIDs)
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	env := NewEnvelope("application/test", []byte("hello"))
	env.AddSignature("mykey", []byte("mysig"))

	data, err := env.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	restored, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if restored.PayloadType != "application/test" {
		t.Errorf("wrong payload type: %s", restored.PayloadType)
	}
	if len(restored.Signatures) != 1 || restored.Signatures[0].KeyID != "mykey" {
		t.Errorf("signatures not preserved: %v", restored.Signatures)
	}

	decoded, _ := restored.DecodePayload()
	if string(decoded) != "hello" {
		t.Errorf("payload not preserved: %q", decoded)
	}
}

func TestPAE(t *testing.T) {
	// PAE format: "DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload
	payloadType := "application/test"
	payload := []byte("hello")

	pae := PAE(payloadType, payload)
	paeStr := string(pae)

	if paeStr[:6] != "DSSEv1" {
		t.Errorf("PAE should start with DSSEv1, got: %q", paeStr[:6])
	}

	// Check it contains the payload type and payload
	if !containsBytes(pae, []byte(payloadType)) {
		t.Error("PAE should contain payload type")
	}
	if !containsBytes(pae, payload) {
		t.Error("PAE should contain payload")
	}
}

func TestUnmarshalInvalidJSON(t *testing.T) {
	_, err := Unmarshal([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestEmptyEnvelope(t *testing.T) {
	env := NewEnvelope("test", []byte{})
	if len(env.Signatures) != 0 {
		t.Error("expected no signatures")
	}
	decoded, _ := env.DecodePayload()
	if len(decoded) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(decoded))
	}
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j, b := range needle {
			if haystack[i+j] != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
