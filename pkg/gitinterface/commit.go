// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package gitinterface

import (
	"errors"
	"fmt"
	"strings"
)

var ErrSigningKeyNotSpecified = errors.New("signing key not specified")

// Commit creates a new commit on the specified reference with the given tree,
// message, and optional signing. The commit's parent is the current tip of
// targetRef (if it exists).
func (r *Repository) Commit(treeID Hash, targetRef, message string, sign bool) (Hash, error) {
	args := []string{"commit-tree", treeID.String(), "-m", message}

	// Add parent if targetRef exists
	parentID, err := r.GetReference(targetRef)
	if err == nil && !parentID.IsZero() {
		args = append(args, "-p", parentID.String())
	}

	if sign {
		args = append(args, "-S")
	}

	output, err := r.executor(args...)
	if err != nil {
		return ZeroHash, fmt.Errorf("creating commit: %w", err)
	}

	commitID, err := NewHash(strings.TrimSpace(output))
	if err != nil {
		return ZeroHash, err
	}

	// Update the reference to point to the new commit
	if err := r.SetReference(targetRef, commitID); err != nil {
		return ZeroHash, fmt.Errorf("updating ref %s: %w", targetRef, err)
	}

	return commitID, nil
}

// CommitUsingSpecificKey creates a commit signed with a specific SSH or GPG
// private key provided as PEM bytes.
func (r *Repository) CommitUsingSpecificKey(treeID Hash, targetRef, message string, signingKeyPEM []byte) (Hash, error) {
	if len(signingKeyPEM) == 0 {
		return ZeroHash, ErrSigningKeyNotSpecified
	}

	// Write key to temp file for git to use
	keyFile, err := writeTempFile(signingKeyPEM)
	if err != nil {
		return ZeroHash, fmt.Errorf("writing signing key: %w", err)
	}
	defer removeFile(keyFile)

	args := []string{
		"-c", fmt.Sprintf("gpg.format=ssh"),
		"-c", fmt.Sprintf("user.signingkey=%s", keyFile),
		"commit-tree", treeID.String(), "-m", message, "-S",
	}

	// Add parent if targetRef exists
	parentID, err := r.GetReference(targetRef)
	if err == nil && !parentID.IsZero() {
		args = append(args, "-p", parentID.String())
	}

	output, err := r.executor(args...)
	if err != nil {
		return ZeroHash, fmt.Errorf("creating signed commit: %w", err)
	}

	commitID, err := NewHash(strings.TrimSpace(output))
	if err != nil {
		return ZeroHash, err
	}

	if err := r.SetReference(targetRef, commitID); err != nil {
		return ZeroHash, fmt.Errorf("updating ref %s: %w", targetRef, err)
	}

	return commitID, nil
}

// GetCommitMessage returns the commit message for the given commit.
func (r *Repository) GetCommitMessage(commitID Hash) (string, error) {
	output, err := r.executor("log", "--format=%B", "-n", "1", commitID.String())
	if err != nil {
		return "", fmt.Errorf("getting commit message: %w", err)
	}
	return strings.TrimRight(output, "\n"), nil
}

// GetCommitTreeID returns the tree hash for the given commit.
func (r *Repository) GetCommitTreeID(commitID Hash) (Hash, error) {
	output, err := r.executor("rev-parse", commitID.String()+"^{tree}")
	if err != nil {
		return ZeroHash, fmt.Errorf("getting commit tree: %w", err)
	}
	return NewHash(strings.TrimSpace(output))
}

// GetCommitParentIDs returns the parent commit hashes.
func (r *Repository) GetCommitParentIDs(commitID Hash) ([]Hash, error) {
	output, err := r.executor("rev-list", "--parents", "-n", "1", commitID.String())
	if err != nil {
		return nil, fmt.Errorf("getting commit parents: %w", err)
	}

	parts := strings.Fields(strings.TrimSpace(output))
	if len(parts) <= 1 {
		return nil, nil // No parents (root commit)
	}

	parents := make([]Hash, 0, len(parts)-1)
	for _, p := range parts[1:] {
		h, err := NewHash(p)
		if err != nil {
			return nil, err
		}
		parents = append(parents, h)
	}

	return parents, nil
}

// KnowsCommit returns true if testCommitID is an ancestor of or equal to
// ancestorCommitID.
func (r *Repository) KnowsCommit(testCommitID, ancestorCommitID Hash) (bool, error) {
	_, err := r.executor("merge-base", "--is-ancestor", ancestorCommitID.String(), testCommitID.String())
	if err != nil {
		// Exit code 1 means not an ancestor, other codes are errors
		if strings.Contains(err.Error(), "exit status 1") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
