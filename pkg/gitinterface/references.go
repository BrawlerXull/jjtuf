// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package gitinterface

import (
	"errors"
	"fmt"
	"strings"
)

var ErrReferenceNotFound = errors.New("reference not found")

// GetReference returns the hash that the named reference points to.
func (r *Repository) GetReference(refName string) (Hash, error) {
	output, err := r.executor("rev-parse", refName)
	if err != nil {
		return ZeroHash, fmt.Errorf("%w: %s", ErrReferenceNotFound, refName)
	}

	return NewHash(strings.TrimSpace(output))
}

// SetReference sets a reference to point to the given hash.
func (r *Repository) SetReference(refName string, gitID Hash) error {
	_, err := r.executor("update-ref", refName, gitID.String())
	return err
}

// DeleteReference deletes the named reference.
func (r *Repository) DeleteReference(refName string) error {
	_, err := r.executor("update-ref", "-d", refName)
	return err
}

// CheckAndSetReference atomically updates a reference from oldID to newID.
func (r *Repository) CheckAndSetReference(refName string, newID, oldID Hash) error {
	_, err := r.executor("update-ref", refName, newID.String(), oldID.String())
	return err
}

// AbsoluteReference resolves a reference to its fully qualified name.
func (r *Repository) AbsoluteReference(target string) (string, error) {
	output, err := r.executor("rev-parse", "--symbolic-full-name", target)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrReferenceNotFound, target)
	}
	return strings.TrimSpace(output), nil
}

// BranchReferenceName returns the fully qualified name for a branch.
func BranchReferenceName(name string) string {
	return "refs/heads/" + name
}

// TagReferenceName returns the fully qualified name for a tag.
func TagReferenceName(name string) string {
	return "refs/tags/" + name
}

// CustomReferenceName returns the name for a custom reference namespace.
func CustomReferenceName(namespace, name string) string {
	return fmt.Sprintf("refs/%s/%s", namespace, name)
}
