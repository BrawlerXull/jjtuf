// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package ssh_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	gorsa "crypto/rsa"
	"encoding/pem"

	"testing"

	gxssh "golang.org/x/crypto/ssh"

	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
	"github.com/jjtuf/jjtuf/internal/signerverifier/ssh"
)

// marshalOpenSSHPrivateKey encodes a private key in OpenSSH PEM format.
func marshalOpenSSHPrivateKey(t *testing.T, key interface{}) []byte {
	t.Helper()
	block, err := gxssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatalf("marshaling OpenSSH private key: %v", err)
	}
	return pem.EncodeToMemory(block)
}

// authorizedKeyLine returns a single authorized_keys line for the given key.
func authorizedKeyLine(t *testing.T, pub interface{}) string {
	t.Helper()
	sshPub, err := gxssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("creating ssh public key: %v", err)
	}
	return string(gxssh.MarshalAuthorizedKey(sshPub))
}

func TestLoadAuthorizedKeyEd25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	line := authorizedKeyLine(t, pub)
	key, err := ssh.LoadSSLibKeyFromAuthorizedKey(line)
	if err != nil {
		t.Fatalf("LoadSSLibKeyFromAuthorizedKey: %v", err)
	}
	if key.KeyType != common.ED25519KeyType {
		t.Errorf("expected %q got %q", common.ED25519KeyType, key.KeyType)
	}
	if key.KeyID == "" {
		t.Error("key ID must not be empty")
	}
}

func TestLoadAuthorizedKeyECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	line := authorizedKeyLine(t, &priv.PublicKey)
	key, err := ssh.LoadSSLibKeyFromAuthorizedKey(line)
	if err != nil {
		t.Fatalf("LoadSSLibKeyFromAuthorizedKey: %v", err)
	}
	if key.KeyType != common.ECDSAKeyType {
		t.Errorf("expected %q got %q", common.ECDSAKeyType, key.KeyType)
	}
}

func TestLoadOpenSSHPrivateKeyEd25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemData := marshalOpenSSHPrivateKey(t, priv)

	sv, err := ssh.LoadSignerVerifierFromOpenSSHKey(pemData)
	if err != nil {
		t.Fatalf("LoadSignerVerifierFromOpenSSHKey: %v", err)
	}

	data := []byte("test message")
	sig, err := sv.Sign(data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := sv.Verify(data, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestLoadOpenSSHPrivateKeyECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemData := marshalOpenSSHPrivateKey(t, priv)

	sv, err := ssh.LoadSignerVerifierFromOpenSSHKey(pemData)
	if err != nil {
		t.Fatalf("LoadSignerVerifierFromOpenSSHKey: %v", err)
	}

	data := []byte("ecdsa test")
	sig, err := sv.Sign(data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := sv.Verify(data, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestAuthorizedKeyAndOpenSSHKeyIDMatch(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Key registered from public key file
	pubKey, err := ssh.LoadSSLibKeyFromAuthorizedKey(authorizedKeyLine(t, pub))
	if err != nil {
		t.Fatalf("LoadSSLibKeyFromAuthorizedKey: %v", err)
	}

	// Signer loaded from private key file
	sv, err := ssh.LoadSignerVerifierFromOpenSSHKey(marshalOpenSSHPrivateKey(t, priv))
	if err != nil {
		t.Fatalf("LoadSignerVerifierFromOpenSSHKey: %v", err)
	}

	if pubKey.KeyID != sv.KeyID() {
		t.Errorf("key ID mismatch: public=%q signer=%q", pubKey.KeyID, sv.KeyID())
	}
}

func TestLoadOpenSSHPrivateKeyRSA(t *testing.T) {
	priv, err := gorsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemData := marshalOpenSSHPrivateKey(t, priv)

	sv, err := ssh.LoadSignerVerifierFromOpenSSHKey(pemData)
	if err != nil {
		t.Fatalf("LoadSignerVerifierFromOpenSSHKey: %v", err)
	}

	data := []byte("rsa test")
	sig, err := sv.Sign(data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := sv.Verify(data, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}
