// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package gitinterface

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrUnknownSigningMethod     = errors.New("unknown signing method")
	ErrIncorrectVerificationKey = errors.New("incorrect verification key")
	ErrSignatureVerification    = errors.New("signature verification failed")
)

// CanSign checks if the repository is configured for commit signing.
func (r *Repository) CanSign() bool {
	output, err := r.executor("config", "--get", "commit.gpgsign")
	if err != nil {
		return false
	}
	return strings.TrimSpace(output) == "true"
}

// VerifySignature verifies the signature on a commit or tag object using the
// given public key. Returns nil if verification succeeds.
func (r *Repository) VerifySignature(objectID Hash) error {
	objType, err := r.GetObjectType(objectID)
	if err != nil {
		return fmt.Errorf("getting object type for verification: %w", err)
	}

	switch objType {
	case CommitObjectType:
		_, err = r.executor("verify-commit", objectID.String())
	case TagObjectType:
		_, err = r.executor("verify-tag", objectID.String())
	default:
		return fmt.Errorf("%w: can only verify commits and tags, got %s", ErrUnknownSigningMethod, objType)
	}

	if err != nil {
		return fmt.Errorf("%w: %s", ErrSignatureVerification, err.Error())
	}

	return nil
}

// GetCommitSignature extracts the raw signature from a commit.
func (r *Repository) GetCommitSignature(commitID Hash) (string, error) {
	output, err := r.executor("log", "--format=%GG", "-n", "1", commitID.String())
	if err != nil {
		return "", fmt.Errorf("getting commit signature: %w", err)
	}
	return strings.TrimSpace(output), nil
}

// GetSigningKeyID extracts the signing key ID from a signed commit.
func (r *Repository) GetSigningKeyID(commitID Hash) (string, error) {
	output, err := r.executor("log", "--format=%GK", "-n", "1", commitID.String())
	if err != nil {
		return "", fmt.Errorf("getting signing key ID: %w", err)
	}
	return strings.TrimSpace(output), nil
}
