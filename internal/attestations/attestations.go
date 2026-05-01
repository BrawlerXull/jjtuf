// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

// Package attestations implements the attestation system for jjtuf.
// Attestations are signed metadata that record additional context for
// repository actions, such as pre-approvals for bookmark updates.
// They are stored in refs/jjtuf/attestations as a Git tree.
package attestations

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"strings"

	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
	"github.com/jjtuf/jjtuf/internal/signerverifier/dsse"
	"github.com/jjtuf/jjtuf/pkg/gitinterface"
)

const (
	// Ref is the Git reference where attestations are stored.
	Ref = "refs/jjtuf/attestations"

	referenceAuthorizationsPath = "reference-authorizations"
	codeReviewApprovalsPath     = "code-review-approvals"

	defaultCommitMessage = "Update attestations"
)

var (
	ErrAttestationsNotFound   = errors.New("attestations not found")
	ErrAuthorizationNotFound  = errors.New("reference authorization not found")
	ErrApprovalNotFound       = errors.New("code review approval not found")
)

// Attestations tracks all attestations in a jjtuf repository.
type Attestations struct {
	// referenceAuthorizations maps authorized actions to blob IDs.
	// Key format: "<bookmark-name>/<from-id>-<to-tree-id>"
	referenceAuthorizations map[string]gitinterface.Hash

	// codeReviewApprovals maps approvals to blob IDs.
	// Key format: "<bookmark-name>/<from-id>-<to-tree-id>/<system>"
	codeReviewApprovals map[string]gitinterface.Hash
}

// NewAttestations creates an empty attestations state.
func NewAttestations() *Attestations {
	return &Attestations{
		referenceAuthorizations: make(map[string]gitinterface.Hash),
		codeReviewApprovals:     make(map[string]gitinterface.Hash),
	}
}

// LoadCurrentAttestations loads attestations from the repository.
func LoadCurrentAttestations(repo *gitinterface.Repository) (*Attestations, error) {
	tipID, err := repo.GetReference(Ref)
	if err != nil {
		// No attestations yet — return empty state
		return NewAttestations(), nil
	}

	return LoadAttestationsFromCommit(repo, tipID)
}

// LoadAttestationsFromCommit loads attestations from a specific commit.
func LoadAttestationsFromCommit(repo *gitinterface.Repository, commitID gitinterface.Hash) (*Attestations, error) {
	treeID, err := repo.GetCommitTreeID(commitID)
	if err != nil {
		return nil, fmt.Errorf("reading attestations tree: %w", err)
	}

	attestations := NewAttestations()

	// Load reference authorizations subtree
	refAuthTreeID, err := repo.GetPathIDInTree(referenceAuthorizationsPath, treeID)
	if err == nil {
		files, err := repo.GetAllFilesInTree(refAuthTreeID)
		if err == nil {
			for filePath, blobID := range files {
				attestations.referenceAuthorizations[filePath] = blobID
			}
		}
	}

	// Load code review approvals subtree
	approvalTreeID, err := repo.GetPathIDInTree(codeReviewApprovalsPath, treeID)
	if err == nil {
		files, err := repo.GetAllFilesInTree(approvalTreeID)
		if err == nil {
			for filePath, blobID := range files {
				attestations.codeReviewApprovals[filePath] = blobID
			}
		}
	}

	return attestations, nil
}

// NormalizeFromID maps the various sentinels jj/jjtuf may emit for a
// "no parent" bookmark transition to a single canonical empty-string form.
// Both attestation storage and lookup MUST go through this function or the
// path written by the producer will not match the path looked up by the
// verifier — silently dropping the attestation from threshold checks.
//
// Inputs that all collapse to "":
//   - empty / whitespace-only
//   - any all-zeros hex string (e.g. "0000…0", "0", "00")
func NormalizeFromID(fromID string) string {
	trimmed := strings.TrimSpace(fromID)
	if strings.Trim(trimmed, "0") == "" {
		return ""
	}
	return trimmed
}

// ReferenceAuthorizationPath returns the storage path for a reference
// authorization attestation. fromID is normalized so that all "no parent"
// sentinels resolve to the same path.
func ReferenceAuthorizationPath(bookmarkName, fromID, toTreeID string) string {
	return path.Join(bookmarkName, fmt.Sprintf("%s-%s", NormalizeFromID(fromID), toTreeID))
}

// CodeReviewApprovalPath returns the storage path for a code review approval.
func CodeReviewApprovalPath(bookmarkName, fromID, toTreeID, system string) string {
	return path.Join(bookmarkName, fmt.Sprintf("%s-%s", NormalizeFromID(fromID), toTreeID), system)
}

// SetReferenceAuthorization stores a reference authorization attestation.
func (a *Attestations) SetReferenceAuthorization(repo *gitinterface.Repository, env *dsse.Envelope, bookmarkName, fromID, toTreeID string) error {
	envBytes, err := env.Marshal()
	if err != nil {
		return fmt.Errorf("serializing attestation: %w", err)
	}

	blobID, err := repo.WriteBlob(envBytes)
	if err != nil {
		return fmt.Errorf("writing attestation blob: %w", err)
	}

	authPath := ReferenceAuthorizationPath(bookmarkName, fromID, toTreeID)
	a.referenceAuthorizations[authPath] = blobID
	return nil
}

// GetReferenceAuthorizationFor retrieves a reference authorization attestation.
func (a *Attestations) GetReferenceAuthorizationFor(repo *gitinterface.Repository, bookmarkName, fromID, toTreeID string) (*dsse.Envelope, error) {
	authPath := ReferenceAuthorizationPath(bookmarkName, fromID, toTreeID)
	blobID, exists := a.referenceAuthorizations[authPath]
	if !exists {
		return nil, ErrAuthorizationNotFound
	}

	envBytes, err := repo.ReadBlob(blobID)
	if err != nil {
		return nil, fmt.Errorf("reading attestation: %w", err)
	}

	return dsse.Unmarshal(envBytes)
}

// GetSignerKeyIDsForAuthorization returns the key IDs whose signatures on the
// reference authorization for the given bookmark transition are cryptographically
// valid against the supplied policy keys.
//
// If policyKeys is nil or empty the function falls back to returning all
// claimed key IDs without verification — useful during bootstrap when no
// policy is loaded yet (the caller is responsible for deciding trust).
func (a *Attestations) GetSignerKeyIDsForAuthorization(repo *gitinterface.Repository, bookmarkName, fromID, toTreeID string, policyKeys ...[]*common.SSLibKey) ([]string, error) {
	env, err := a.GetReferenceAuthorizationFor(repo, bookmarkName, fromID, toTreeID)
	if err != nil {
		return nil, err
	}

	// Flatten the variadic policy-keys argument.
	var keys []*common.SSLibKey
	for _, ks := range policyKeys {
		keys = append(keys, ks...)
	}

	if len(keys) == 0 {
		// No keys to verify against — return claimed IDs as-is.
		slog.Debug("GetSignerKeyIDsForAuthorization: no policy keys supplied, returning unverified key IDs")
		return env.GetSignerKeyIDs(), nil
	}

	validKeyIDs, err := env.VerifySignatures(keys)
	if err != nil {
		return nil, fmt.Errorf("verifying authorization signatures: %w", err)
	}
	return validKeyIDs, nil
}

// SetCodeReviewApproval stores a code review approval attestation.
func (a *Attestations) SetCodeReviewApproval(repo *gitinterface.Repository, env *dsse.Envelope, bookmarkName, fromID, toTreeID, system string) error {
	envBytes, err := env.Marshal()
	if err != nil {
		return fmt.Errorf("serializing approval: %w", err)
	}

	blobID, err := repo.WriteBlob(envBytes)
	if err != nil {
		return fmt.Errorf("writing approval blob: %w", err)
	}

	approvalPath := CodeReviewApprovalPath(bookmarkName, fromID, toTreeID, system)
	a.codeReviewApprovals[approvalPath] = blobID
	return nil
}

// GetCodeReviewApproval retrieves a code review approval attestation.
func (a *Attestations) GetCodeReviewApproval(repo *gitinterface.Repository, bookmarkName, fromID, toTreeID, system string) (*dsse.Envelope, error) {
	approvalPath := CodeReviewApprovalPath(bookmarkName, fromID, toTreeID, system)
	blobID, exists := a.codeReviewApprovals[approvalPath]
	if !exists {
		return nil, ErrApprovalNotFound
	}

	envBytes, err := repo.ReadBlob(blobID)
	if err != nil {
		return nil, fmt.Errorf("reading approval: %w", err)
	}

	return dsse.Unmarshal(envBytes)
}

// Commit writes the current attestations state to the attestations ref.
func (a *Attestations) Commit(repo *gitinterface.Repository) error {
	// Build the attestation tree structure
	entries := make(map[string]gitinterface.Hash)

	// Add reference authorizations
	for authPath, blobID := range a.referenceAuthorizations {
		entries[path.Join(referenceAuthorizationsPath, authPath)] = blobID
	}

	// Add code review approvals
	for approvalPath, blobID := range a.codeReviewApprovals {
		entries[path.Join(codeReviewApprovalsPath, approvalPath)] = blobID
	}

	if len(entries) == 0 {
		// Create empty tree
		treeID, err := repo.EmptyTree()
		if err != nil {
			return err
		}
		_, err = repo.Commit(treeID, Ref, defaultCommitMessage, false)
		return err
	}

	tb := gitinterface.NewTreeBuilder(repo)
	treeID, err := tb.WriteRootTreeFromBlobIDs(entries)
	if err != nil {
		return fmt.Errorf("creating attestations tree: %w", err)
	}

	_, err = repo.Commit(treeID, Ref, defaultCommitMessage, false)
	return err
}

// ListReferenceAuthorizations returns all reference authorization paths.
func (a *Attestations) ListReferenceAuthorizations() []string {
	paths := make([]string, 0, len(a.referenceAuthorizations))
	for p := range a.referenceAuthorizations {
		paths = append(paths, p)
	}
	return paths
}

// ListCodeReviewApprovals returns all code review approval paths.
func (a *Attestations) ListCodeReviewApprovals() []string {
	paths := make([]string, 0, len(a.codeReviewApprovals))
	for p := range a.codeReviewApprovals {
		paths = append(paths, p)
	}
	return paths
}

// FindAuthorizationsForBookmark returns all authorization key IDs for transitions
// of the given bookmark that match the from/to pattern.
func (a *Attestations) FindAuthorizationsForBookmark(repo *gitinterface.Repository, bookmarkName string) (map[string][]string, error) {
	result := make(map[string][]string) // authPath -> signerKeyIDs

	prefix := bookmarkName + "/"
	for authPath, blobID := range a.referenceAuthorizations {
		if !strings.HasPrefix(authPath, prefix) {
			continue
		}

		envBytes, err := repo.ReadBlob(blobID)
		if err != nil {
			continue
		}

		env, err := dsse.Unmarshal(envBytes)
		if err != nil {
			continue
		}

		result[authPath] = env.GetSignerKeyIDs()
	}

	return result, nil
}

// ensure json is importable
var _ = json.Marshal
