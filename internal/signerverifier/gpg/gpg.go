// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

// Package gpg implements GPG-based signing and verification via the system
// gpg binary. This is intentional: jjtuf delegates key management and the
// web-of-trust model to GPG rather than re-implementing them.
package gpg

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
)

var (
	ErrGPGNotFound    = errors.New("gpg binary not found in PATH")
	ErrNoGPGKey       = errors.New("no GPG key specified")
	ErrSigningFailed  = errors.New("gpg signing failed")
	ErrVerifyFailed   = errors.New("gpg verification failed")
)

// SignerVerifier implements common.SignerVerifier using the system gpg binary.
type SignerVerifier struct {
	// fingerprint is the full 40-character GPG key fingerprint.
	fingerprint string
	ssKey       *common.SSLibKey
}

// New creates a GPG SignerVerifier for the given key fingerprint.
// The fingerprint must identify a key present in the local GPG keyring.
func New(fingerprint string) (*SignerVerifier, error) {
	fingerprint = strings.ToUpper(strings.ReplaceAll(fingerprint, " ", ""))
	if fingerprint == "" {
		return nil, ErrNoGPGKey
	}
	if _, err := exec.LookPath("gpg"); err != nil {
		return nil, ErrGPGNotFound
	}

	// Derive the key ID (last 16 hex chars of the fingerprint).
	keyID := fingerprint
	if len(fingerprint) > 16 {
		keyID = fingerprint[len(fingerprint)-16:]
	}

	ssKey := &common.SSLibKey{
		KeyID:   keyID,
		KeyType: common.GPGKeyType,
		Scheme:  common.GPGSigningScheme,
		KeyVal:  common.KeyVal{Identity: fingerprint},
	}

	return &SignerVerifier{fingerprint: fingerprint, ssKey: ssKey}, nil
}

// NewVerifierFromSSLibKey creates a verify-only GPG SignerVerifier from an SSLibKey.
func NewVerifierFromSSLibKey(key *common.SSLibKey) (*SignerVerifier, error) {
	identity := key.KeyVal.Identity
	if identity == "" {
		identity = key.KeyID
	}
	return &SignerVerifier{fingerprint: identity, ssKey: key}, nil
}

// Sign signs data using the GPG key identified by the fingerprint, returning
// a detached binary signature.
func (s *SignerVerifier) Sign(data []byte) ([]byte, error) {
	args := []string{
		"--batch", "--no-tty",
		"--local-user", s.fingerprint,
		"--detach-sign", "--armor",
		"-",
	}
	cmd := exec.Command("gpg", args...)
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("%w: %s", ErrSigningFailed, string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("%w: %v", ErrSigningFailed, err)
	}
	return out, nil
}

// Verify verifies a detached GPG signature over data.
func (s *SignerVerifier) Verify(data, sig []byte) error {
	// Write data and sig to temp pipes via stdin/process substitution is awkward;
	// we use a temp file for the signature only.
	sigFile, err := writeTempFile("jjtuf-gpg-sig-*.asc", sig)
	if err != nil {
		return fmt.Errorf("writing temp signature file: %w", err)
	}
	defer removeFile(sigFile)

	args := []string{
		"--batch", "--no-tty",
		"--verify", sigFile, "-",
	}
	cmd := exec.Command("gpg", args...)
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", ErrVerifyFailed, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *SignerVerifier) KeyID() string            { return s.ssKey.KeyID }
func (s *SignerVerifier) Public() *common.SSLibKey { return s.ssKey }

// writeTempFile writes data to a temp file with the given pattern and returns
// its path.
func writeTempFile(pattern string, data []byte) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return "", err
	}
	return f.Name(), nil
}

func removeFile(path string) { os.Remove(path) }
