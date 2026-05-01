// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package ed25519_test

import (
	"crypto/rand"
	goed25519 "crypto/ed25519"
	"testing"

	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
	"github.com/jjtuf/jjtuf/internal/signerverifier/ed25519"
)

func generateKey(t *testing.T) (goed25519.PublicKey, goed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := goed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ed25519 key: %v", err)
	}
	return pub, priv
}

func TestSignAndVerify(t *testing.T) {
	_, priv := generateKey(t)
	sv, err := ed25519.New(priv)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	data := []byte("hello jjtuf")
	sig, err := sv.Sign(data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := sv.Verify(data, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsBadSignature(t *testing.T) {
	_, priv := generateKey(t)
	sv, _ := ed25519.New(priv)

	data := []byte("legitimate data")
	sig, _ := sv.Sign(data)

	// Corrupt one byte
	sig[0] ^= 0xFF
	if err := sv.Verify(data, sig); err == nil {
		t.Fatal("Verify should have rejected corrupted signature")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv1 := generateKey(t)
	_, priv2 := generateKey(t)
	sv1, _ := ed25519.New(priv1)
	sv2, _ := ed25519.New(priv2)

	data := []byte("some data")
	sig, _ := sv1.Sign(data)

	if err := sv2.Verify(data, sig); err == nil {
		t.Fatal("Verify should have rejected signature from wrong key")
	}
}

func TestVerifyOnlyNoPrivateKey(t *testing.T) {
	pub, _ := generateKey(t)
	sv, err := ed25519.NewVerifier(pub)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	if _, err := sv.Sign([]byte("data")); err == nil {
		t.Fatal("Sign on verify-only signer should fail")
	}
}

func TestKeyIDIsConsistent(t *testing.T) {
	pub, priv := generateKey(t)

	sv1, _ := ed25519.New(priv)
	sv2, _ := ed25519.NewVerifier(pub)

	if sv1.KeyID() != sv2.KeyID() {
		t.Errorf("key IDs differ: signer=%q verifier=%q", sv1.KeyID(), sv2.KeyID())
	}

	if sv1.KeyID() == "" {
		t.Error("key ID must not be empty")
	}
}

func TestRoundTripViaSSLibKey(t *testing.T) {
	_, priv := generateKey(t)
	sv, _ := ed25519.New(priv)
	ssKey := sv.Public()

	if ssKey.KeyType != common.ED25519KeyType {
		t.Errorf("expected keytype %q got %q", common.ED25519KeyType, ssKey.KeyType)
	}
	if ssKey.Scheme != common.ED25519SigningScheme {
		t.Errorf("expected scheme %q got %q", common.ED25519SigningScheme, ssKey.Scheme)
	}
	if ssKey.KeyID == "" {
		t.Error("key ID must not be empty")
	}

	// Reconstruct verifier from SSLibKey and verify a signature
	verifier, err := ed25519.NewVerifierFromSSLibKey(ssKey)
	if err != nil {
		t.Fatalf("NewVerifierFromSSLibKey: %v", err)
	}

	data := []byte("round-trip test")
	sig, _ := sv.Sign(data)
	if err := verifier.Verify(data, sig); err != nil {
		t.Fatalf("round-trip verify failed: %v", err)
	}
}
