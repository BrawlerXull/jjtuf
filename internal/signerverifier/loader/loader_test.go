// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package loader_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	gorsa "crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	gxssh "golang.org/x/crypto/ssh"

	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
	"github.com/jjtuf/jjtuf/internal/signerverifier/loader"
)

// helpers to write key files

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

func pkcs8PEM(t *testing.T, key interface{}) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func openSSHPEM(t *testing.T, key interface{}) []byte {
	t.Helper()
	block, err := gxssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	return pem.EncodeToMemory(block)
}

func pkixPubPEM(t *testing.T, pub interface{}) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func authorizedKey(t *testing.T, pub interface{}) []byte {
	t.Helper()
	sshPub, err := gxssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return gxssh.MarshalAuthorizedKey(sshPub)
}

// ── Private key loading ──────────────────────────────────────────────────────

func TestLoadPKCS8Ed25519(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	path := writeFile(t, dir, "key.pem", pkcs8PEM(t, priv))

	sv, err := loader.LoadSignerVerifierFromFile(path)
	if err != nil {
		t.Fatalf("LoadSignerVerifierFromFile: %v", err)
	}
	roundTripSign(t, sv)
}

func TestLoadPKCS8ECDSA(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dir := t.TempDir()
	path := writeFile(t, dir, "key.pem", pkcs8PEM(t, priv))

	sv, err := loader.LoadSignerVerifierFromFile(path)
	if err != nil {
		t.Fatalf("LoadSignerVerifierFromFile: %v", err)
	}
	roundTripSign(t, sv)
}

func TestLoadOpenSSHEd25519(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	path := writeFile(t, dir, "id_ed25519", openSSHPEM(t, priv))

	sv, err := loader.LoadSignerVerifierFromFile(path)
	if err != nil {
		t.Fatalf("LoadSignerVerifierFromFile: %v", err)
	}
	roundTripSign(t, sv)

	// Verify key ID matches public key loaded separately
	pubKeyPath := writeFile(t, dir, "id_ed25519.pub", authorizedKey(t, pub))
	ssKey, err := loader.LoadSSLibKeyFromPublicKeyFile(pubKeyPath)
	if err != nil {
		t.Fatalf("LoadSSLibKeyFromPublicKeyFile: %v", err)
	}
	if sv.KeyID() != ssKey.KeyID {
		t.Errorf("key ID mismatch: private=%q public=%q", sv.KeyID(), ssKey.KeyID)
	}
}

// ── Public key loading ───────────────────────────────────────────────────────

func TestLoadPKIXPublicKeyEd25519(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	path := writeFile(t, dir, "pub.pem", pkixPubPEM(t, pub))

	ssKey, err := loader.LoadSSLibKeyFromPublicKeyFile(path)
	if err != nil {
		t.Fatalf("LoadSSLibKeyFromPublicKeyFile: %v", err)
	}
	if ssKey.KeyType != common.ED25519KeyType {
		t.Errorf("expected %q got %q", common.ED25519KeyType, ssKey.KeyType)
	}
}

func TestLoadAuthorizedKeyEd25519(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	path := writeFile(t, dir, "id_ed25519.pub", authorizedKey(t, pub))

	ssKey, err := loader.LoadSSLibKeyFromPublicKeyFile(path)
	if err != nil {
		t.Fatalf("LoadSSLibKeyFromPublicKeyFile: %v", err)
	}
	if ssKey.KeyType != common.ED25519KeyType {
		t.Errorf("expected %q got %q", common.ED25519KeyType, ssKey.KeyType)
	}
}

func TestLoadVerifierFromSSLibKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sv, _ := loader.LoadSignerVerifierFromPEM(pkcs8PEM(t, priv))
	ssKey := sv.Public()

	verifier, err := loader.LoadVerifierFromSSLibKey(ssKey)
	if err != nil {
		t.Fatalf("LoadVerifierFromSSLibKey: %v", err)
	}

	data := []byte("loader round-trip")
	sig, _ := sv.Sign(data)
	if err := verifier.Verify(data, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestLoadRSAKey(t *testing.T) {
	priv, _ := gorsa.GenerateKey(rand.Reader, 2048)
	dir := t.TempDir()
	path := writeFile(t, dir, "key.pem", pkcs8PEM(t, priv))

	sv, err := loader.LoadSignerVerifierFromFile(path)
	if err != nil {
		t.Fatalf("LoadSignerVerifierFromFile: %v", err)
	}
	roundTripSign(t, sv)
}

// roundTripSign signs and verifies data using the same signer/verifier.
func roundTripSign(t *testing.T, sv common.SignerVerifier) {
	t.Helper()
	data := []byte("round-trip verification test")
	sig, err := sv.Sign(data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := sv.Verify(data, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}
