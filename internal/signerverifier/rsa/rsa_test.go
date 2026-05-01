// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package rsa_test

import (
	"crypto/rand"
	gorsa "crypto/rsa"
	"testing"

	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
	"github.com/jjtuf/jjtuf/internal/signerverifier/rsa"
)

func generateKey(t *testing.T) *gorsa.PrivateKey {
	t.Helper()
	key, err := gorsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating rsa key: %v", err)
	}
	return key
}

func TestSignAndVerify(t *testing.T) {
	sv, err := rsa.New(generateKey(t))
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
	sv, _ := rsa.New(generateKey(t))
	data := []byte("data")
	sig, _ := sv.Sign(data)
	sig[0] ^= 0xFF
	if err := sv.Verify(data, sig); err == nil {
		t.Fatal("should have rejected corrupted signature")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	sv1, _ := rsa.New(generateKey(t))
	sv2, _ := rsa.New(generateKey(t))
	data := []byte("data")
	sig, _ := sv1.Sign(data)
	if err := sv2.Verify(data, sig); err == nil {
		t.Fatal("should have rejected signature from wrong key")
	}
}

func TestVerifyOnlyNoPrivateKey(t *testing.T) {
	priv := generateKey(t)
	sv, err := rsa.NewVerifier(&priv.PublicKey)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := sv.Sign([]byte("data")); err == nil {
		t.Fatal("Sign on verify-only signer should fail")
	}
}

func TestKeyIDConsistency(t *testing.T) {
	priv := generateKey(t)
	sv1, _ := rsa.New(priv)
	sv2, _ := rsa.NewVerifier(&priv.PublicKey)
	if sv1.KeyID() != sv2.KeyID() {
		t.Errorf("key IDs differ: signer=%q verifier=%q", sv1.KeyID(), sv2.KeyID())
	}
}

func TestRoundTripViaSSLibKey(t *testing.T) {
	sv, _ := rsa.New(generateKey(t))
	ssKey := sv.Public()

	if ssKey.KeyType != common.RSAKeyType {
		t.Errorf("expected keytype %q got %q", common.RSAKeyType, ssKey.KeyType)
	}

	verifier, err := rsa.NewVerifierFromSSLibKey(ssKey)
	if err != nil {
		t.Fatalf("NewVerifierFromSSLibKey: %v", err)
	}

	data := []byte("round-trip")
	sig, _ := sv.Sign(data)
	if err := verifier.Verify(data, sig); err != nil {
		t.Fatalf("round-trip verify: %v", err)
	}
}
