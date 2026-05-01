// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package dsse_test

import (
	"crypto/rand"
	goed25519 "crypto/ed25519"
	"testing"

	siged25519 "github.com/jjtuf/jjtuf/internal/signerverifier/ed25519"
	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
	"github.com/jjtuf/jjtuf/internal/signerverifier/dsse"
	"github.com/jjtuf/jjtuf/internal/signerverifier/loader"
)

func init() {
	dsse.SetDefaultLoader(loader.LoadVerifierFromSSLibKey)
}

func newEd25519Signer(t *testing.T) (common.SignerVerifier, *common.SSLibKey) {
	t.Helper()
	_, priv, err := goed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	sv, err := siged25519.New(priv)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	return sv, sv.Public()
}

func TestSignAndVerifySignatures(t *testing.T) {
	signer, pub := newEd25519Signer(t)

	env := dsse.NewEnvelope("application/json", []byte(`{"hello":"world"}`))
	if err := env.Sign(signer); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	validKeyIDs, err := env.VerifySignatures([]*common.SSLibKey{pub})
	if err != nil {
		t.Fatalf("VerifySignatures: %v", err)
	}
	if len(validKeyIDs) != 1 || validKeyIDs[0] != signer.KeyID() {
		t.Errorf("expected valid key ID %q got %v", signer.KeyID(), validKeyIDs)
	}
}

func TestVerifySignaturesMultipleSigners(t *testing.T) {
	sv1, pub1 := newEd25519Signer(t)
	sv2, pub2 := newEd25519Signer(t)

	env := dsse.NewEnvelope("application/json", []byte(`{"data":1}`))
	if err := env.Sign(sv1); err != nil {
		t.Fatalf("Sign sv1: %v", err)
	}
	if err := env.Sign(sv2); err != nil {
		t.Fatalf("Sign sv2: %v", err)
	}

	validKeyIDs, err := env.VerifySignatures([]*common.SSLibKey{pub1, pub2})
	if err != nil {
		t.Fatalf("VerifySignatures: %v", err)
	}
	if len(validKeyIDs) != 2 {
		t.Errorf("expected 2 valid key IDs got %d: %v", len(validKeyIDs), validKeyIDs)
	}
}

func TestVerifySignaturesUnknownKeyFiltered(t *testing.T) {
	sv, pub := newEd25519Signer(t)
	_, unknownPub := newEd25519Signer(t)

	env := dsse.NewEnvelope("test", []byte("payload"))
	_ = env.Sign(sv)

	// Only the known key should count
	validKeyIDs, err := env.VerifySignatures([]*common.SSLibKey{pub, unknownPub})
	if err != nil {
		t.Fatalf("VerifySignatures: %v", err)
	}
	if len(validKeyIDs) != 1 {
		t.Errorf("expected 1 valid key ID got %d", len(validKeyIDs))
	}
}

func TestVerifySignaturesNoMatchingKey(t *testing.T) {
	sv, _ := newEd25519Signer(t)
	_, otherPub := newEd25519Signer(t)

	env := dsse.NewEnvelope("test", []byte("payload"))
	_ = env.Sign(sv)

	_, err := env.VerifySignatures([]*common.SSLibKey{otherPub})
	if err == nil {
		t.Fatal("expected error when no matching keys")
	}
}

func TestVerifySignaturesNoSignatures(t *testing.T) {
	_, pub := newEd25519Signer(t)
	env := dsse.NewEnvelope("test", []byte("unsigned payload"))

	_, err := env.VerifySignatures([]*common.SSLibKey{pub})
	if err == nil {
		t.Fatal("expected error for envelope with no signatures")
	}
}

func TestSignatureIsOverPAENotRawPayload(t *testing.T) {
	sv, pub := newEd25519Signer(t)
	env := dsse.NewEnvelope("application/json", []byte(`{"x":1}`))
	_ = env.Sign(sv)

	// Verify passes with correct keys
	if _, err := env.VerifySignatures([]*common.SSLibKey{pub}); err != nil {
		t.Fatalf("should verify: %v", err)
	}

	// A tampered payload type should invalidate the signature
	env.PayloadType = "application/tampered"
	if _, err := env.VerifySignatures([]*common.SSLibKey{pub}); err == nil {
		t.Fatal("tampered payload type should fail verification")
	}
}
