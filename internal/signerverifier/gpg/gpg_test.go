// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package gpg_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
	"github.com/jjtuf/jjtuf/internal/signerverifier/gpg"
)

// skipIfNoGPG skips the test when the gpg binary is not available in PATH.
func skipIfNoGPG(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg binary not found in PATH; skipping integration test")
	}
}

// gpgBatchParams is the batch key-generation parameter file content.
const gpgBatchParams = `%no-protection
Key-Type: RSA
Key-Length: 2048
Name-Real: jjtuf Test
Name-Email: jjtuf-test@test.invalid
Expire-Date: 1d
%commit
`

// generateTestKey generates a temporary GPG key and returns its fingerprint.
// The caller is responsible for deleting the key via deleteTestKey.
func generateTestKey(t *testing.T) string {
	t.Helper()

	// Write batch params to a temp file inside the test's temp dir.
	batchFile := t.TempDir() + "/keygen-batch"
	if err := os.WriteFile(batchFile, []byte(gpgBatchParams), 0600); err != nil {
		t.Fatalf("writing batch params: %v", err)
	}

	cmd := exec.Command("gpg", "--batch", "--gen-key", batchFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("gpg --gen-key failed: %v\n%s", err, out)
	}

	// Retrieve the fingerprint for the newly generated key.
	fpCmd := exec.Command("gpg", "--with-colons", "--fingerprint", "jjtuf-test@test.invalid")
	fpOut, err := fpCmd.Output()
	if err != nil {
		t.Fatalf("gpg --fingerprint failed: %v", err)
	}

	fp := extractFingerprint(string(fpOut))
	if fp == "" {
		t.Fatalf("could not extract fingerprint from gpg output:\n%s", fpOut)
	}
	return fp
}

// deleteTestKey removes a key (secret + public) from the keyring by fingerprint.
func deleteTestKey(t *testing.T, fingerprint string) {
	t.Helper()
	cmd := exec.Command("gpg", "--batch", "--yes", "--delete-secret-and-public-key", fingerprint)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("warning: deleting test key %s: %v\n%s", fingerprint, err, out)
	}
}

// extractFingerprint parses gpg --with-colons --fingerprint output and returns
// the first fingerprint found (the "fpr" record).
func extractFingerprint(output string) string {
	for _, line := range strings.Split(output, "\n") {
		parts := strings.Split(line, ":")
		if len(parts) >= 10 && parts[0] == "fpr" {
			fp := strings.TrimSpace(parts[9])
			if fp != "" {
				return fp
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestGPGSignVerifyRoundTrip(t *testing.T) {
	skipIfNoGPG(t)

	// Use an isolated GNUPGHOME so we don't pollute the real keyring.
	gnupgHome := t.TempDir()
	t.Setenv("GNUPGHOME", gnupgHome)

	fingerprint := generateTestKey(t)
	t.Cleanup(func() { deleteTestKey(t, fingerprint) })

	sv, err := gpg.New(fingerprint)
	if err != nil {
		t.Fatalf("gpg.New: %v", err)
	}

	data := []byte("hello from jjtuf integration test")

	sig, err := sv.Sign(data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty signature")
	}

	if err := sv.Verify(data, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Verify that a different payload does not pass.
	if err := sv.Verify([]byte("tampered"), sig); err == nil {
		t.Error("Verify should have rejected signature over different data")
	}
}

func TestGPGSignWithMissingKey(t *testing.T) {
	skipIfNoGPG(t)

	// Use a fresh, empty GNUPGHOME so no keys are present.
	gnupgHome := t.TempDir()
	t.Setenv("GNUPGHOME", gnupgHome)

	nonExistentFingerprint := fmt.Sprintf("%040X", bytes.Repeat([]byte{0xDE}, 20))

	sv, err := gpg.New(nonExistentFingerprint)
	if err != nil {
		t.Fatalf("gpg.New (key construction) unexpected error: %v", err)
	}

	_, err = sv.Sign([]byte("data"))
	if err == nil {
		t.Fatal("expected Sign to fail when the key is not in the keyring")
	}
}

func TestNewVerifierFromSSLibKey(t *testing.T) {
	skipIfNoGPG(t)

	fingerprint := "AABBCCDDEEFF00112233445566778899AABBCCDD"
	ssKey := &common.SSLibKey{
		KeyID:   "myKeyID",
		KeyType: common.GPGKeyType,
		Scheme:  common.GPGSigningScheme,
		KeyVal:  common.KeyVal{Identity: fingerprint},
	}

	sv, err := gpg.NewVerifierFromSSLibKey(ssKey)
	if err != nil {
		t.Fatalf("NewVerifierFromSSLibKey: %v", err)
	}

	if sv.KeyID() != "myKeyID" {
		t.Errorf("KeyID() = %q, want %q", sv.KeyID(), "myKeyID")
	}

	pub := sv.Public()
	if pub == nil {
		t.Fatal("Public() returned nil")
	}
	if pub.KeyType != common.GPGKeyType {
		t.Errorf("KeyType = %q, want %q", pub.KeyType, common.GPGKeyType)
	}
	if pub.KeyVal.Identity != fingerprint {
		t.Errorf("Identity = %q, want %q", pub.KeyVal.Identity, fingerprint)
	}
}
