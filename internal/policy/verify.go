// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/jjtuf/jjtuf/internal/attestations"
	"github.com/jjtuf/jjtuf/internal/osl"
	"github.com/jjtuf/jjtuf/pkg/gitinterface"
)

var (
	ErrVerificationFailed    = errors.New("jjtuf policy verification failed")
	ErrInvalidEntryNotSkipped = errors.New("invalid entry found not marked as skipped")
	ErrNoRulesForNamespace   = errors.New("no policy rules found for namespace")
)

// VerificationResult contains the outcome of verifying an OSL entry.
type VerificationResult struct {
	// EntryID is the OSL entry that was verified.
	EntryID gitinterface.Hash

	// Passed indicates whether all checks passed.
	Passed bool

	// Violations lists any policy violations found.
	Violations []Violation
}

// Violation describes a single policy violation.
type Violation struct {
	// BookmarkName is the affected bookmark.
	BookmarkName string

	// Rule is the rule that was violated (may be nil if no rule matched).
	RuleName string

	// Message describes the violation.
	Message string
}

// PolicyVerifier implements jjtuf verification workflows.
type PolicyVerifier struct {
	repo *gitinterface.Repository
}

// NewPolicyVerifier creates a new verifier for the given repository.
func NewPolicyVerifier(repo *gitinterface.Repository) *PolicyVerifier {
	return &PolicyVerifier{repo: repo}
}

// VerifyRef verifies the latest OSL entry for the target bookmark using the
// current policy. Returns the expected commit ID if verification succeeds.
func (v *PolicyVerifier) VerifyRef(target string) (*VerificationResult, error) {
	slog.Debug(fmt.Sprintf("Identifying latest OSL entry for '%s'...", target))
	latestEntry, err := osl.GetLatestOperationEntryFor(v.repo, target)
	if err != nil {
		return nil, fmt.Errorf("finding OSL entry for %s: %w", target, err)
	}

	return v.verifyEntry(latestEntry, target)
}

// VerifyRefFull verifies the entire OSL history for the target bookmark.
func (v *PolicyVerifier) VerifyRefFull(target string) ([]*VerificationResult, error) {
	slog.Debug(fmt.Sprintf("Verifying full history for '%s'...", target))

	// Collect all entries for this bookmark (oldest first)
	var entries []*osl.OperationEntry
	err := osl.IterateEntries(v.repo, func(entry osl.Entry) bool {
		opEntry, ok := entry.(*osl.OperationEntry)
		if !ok {
			return true
		}
		for _, delta := range opEntry.BookmarkDeltas {
			if delta.Name == target {
				entries = append(entries, opEntry)
				break
			}
		}
		return true
	})
	if err != nil {
		return nil, err
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("no OSL entries found for bookmark %q", target)
	}

	// Reverse to get oldest-first order
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}

	// Verify each entry
	var results []*VerificationResult
	for _, entry := range entries {
		result, err := v.verifyEntry(entry, target)
		if err != nil {
			return results, err
		}
		results = append(results, result)
	}

	return results, nil
}

// verifyEntry verifies a single OSL entry against the current policy.
func (v *PolicyVerifier) verifyEntry(entry *osl.OperationEntry, target string) (*VerificationResult, error) {
	result := &VerificationResult{
		EntryID: entry.ID,
		Passed:  true,
	}

	// Load current policy state
	slog.Debug("Loading policy state...")
	state, err := LoadCurrentState(v.repo)
	if err != nil {
		return nil, fmt.Errorf("loading policy: %w", err)
	}

	// If no targets metadata (no rules defined), pass by default
	if state.TargetsMetadata == nil {
		slog.Debug("No policy rules defined, verification passes by default")
		return result, nil
	}

	// Check global rules first
	globalRules := state.RootMetadata.GetGlobalRules()
	for _, delta := range entry.BookmarkDeltas {
		if delta.Name != target {
			continue
		}

		// Check block-force-pushes global rule
		if blockRules, exists := globalRules["block-force-pushes"]; exists {
			for _, rule := range blockRules {
				namespace := fmt.Sprintf("bookmark:%s", delta.Name)
				for _, pattern := range rule.Patterns() {
					if matchesNamespace(pattern, namespace) {
						// A force push is detected when FromID is non-empty but
						// the new commit is not a descendant of the old commit
						if delta.FromID != "" && delta.ToID != "" && !delta.Conflict {
							fromHash, err1 := gitinterface.NewHash(delta.FromID)
							toHash, err2 := gitinterface.NewHash(delta.ToID)
							if err1 == nil && err2 == nil {
								isDescendant, err := v.repo.KnowsCommit(toHash, fromHash)
								if err == nil && !isDescendant {
									result.Passed = false
									result.Violations = append(result.Violations, Violation{
										BookmarkName: delta.Name,
										RuleName:     rule.Name(),
										Message:      fmt.Sprintf("global rule %q: force push blocked on %s", rule.Name(), delta.Name),
									})
								}
							}
						}
					}
				}
			}
		}
	}

	// Get the signing key ID from the OSL entry's commit
	signerKeyID, err := v.repo.GetSigningKeyID(entry.ID)
	if err != nil {
		slog.Debug(fmt.Sprintf("Could not get signing key ID: %v", err))
	}

	// Verify each bookmark delta in the entry
	for _, delta := range entry.BookmarkDeltas {
		if delta.Name != target {
			continue
		}

		namespace := fmt.Sprintf("bookmark:%s", delta.Name)
		slog.Debug(fmt.Sprintf("Finding rules for namespace '%s'...", namespace))

		rules := state.FindRulesForNamespace(namespace)
		if len(rules) == 0 {
			// No rules protect this namespace — implicitly allowed
			slog.Debug(fmt.Sprintf("No rules protect %s, implicitly allowed", namespace))
			continue
		}

		// Load attestation signatures for this bookmark transition
		currentAttestations, err := attestations.LoadCurrentAttestations(v.repo)
		if err != nil {
			slog.Debug(fmt.Sprintf("Could not load attestations: %v", err))
		}

		// Check each matching rule
		for _, rule := range rules {
			verifier := NewSignatureVerifier(rule, state)

			// Collect signer IDs from commit signature
			var signerKeyIDs []string
			if signerKeyID != "" {
				signerKeyIDs = append(signerKeyIDs, signerKeyID)
			}

			// Collect signer IDs from attestations
			if currentAttestations != nil && delta.FromID != "" && delta.ToID != "" {
				// Try to find a reference authorization for this transition
				// We need the tree ID of the target commit, not the commit ID
				toTreeID := delta.ToID
				if toCommitTreeID, err := v.repo.GetCommitTreeID(gitinterface.Hash(toTreeID)); err == nil {
					toTreeID = toCommitTreeID.String()
				}

				authKeyIDs, err := currentAttestations.GetSignerKeyIDsForAuthorization(
					v.repo, delta.Name, delta.FromID, toTreeID)
				if err == nil {
					signerKeyIDs = append(signerKeyIDs, authKeyIDs...)
				}
			}

			err := verifier.Verify(signerKeyIDs)
			if err != nil {
				result.Passed = false
				result.Violations = append(result.Violations, Violation{
					BookmarkName: delta.Name,
					RuleName:     rule.ID(),
					Message:      fmt.Sprintf("rule %q: %s", rule.ID(), err.Error()),
				})
			}
		}
	}

	return result, nil
}

// VerifyFileChanges verifies that file-level changes in a commit are authorized.
// This checks "file:<path>" namespace rules.
func (v *PolicyVerifier) VerifyFileChanges(state *State, fromCommitID, toCommitID gitinterface.Hash, signerKeyIDs []string) ([]Violation, error) {
	if state.TargetsMetadata == nil {
		return nil, nil
	}

	// Get changed files between commits
	var changedFiles map[string]gitinterface.Hash
	var err error

	if fromCommitID.IsZero() {
		// First commit — all files are "changed"
		treeID, err := v.repo.GetCommitTreeID(toCommitID)
		if err != nil {
			return nil, fmt.Errorf("getting commit tree: %w", err)
		}
		changedFiles, err = v.repo.GetAllFilesInTree(treeID)
		if err != nil {
			return nil, fmt.Errorf("listing files in tree: %w", err)
		}
	} else {
		// Diff between two commits
		fromTree, err1 := v.repo.GetCommitTreeID(fromCommitID)
		toTree, err2 := v.repo.GetCommitTreeID(toCommitID)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("getting commit trees: %v / %v", err1, err2)
		}

		fromFiles, _ := v.repo.GetAllFilesInTree(fromTree)
		toFiles, err := v.repo.GetAllFilesInTree(toTree)
		if err != nil {
			return nil, fmt.Errorf("listing files: %w", err)
		}

		changedFiles = make(map[string]gitinterface.Hash)
		for path, hash := range toFiles {
			oldHash, existed := fromFiles[path]
			if !existed || !oldHash.Equal(hash) {
				changedFiles[path] = hash
			}
		}
		// Check for deletions
		for path := range fromFiles {
			if _, exists := toFiles[path]; !exists {
				changedFiles[path] = gitinterface.ZeroHash
			}
		}
	}

	// Check each changed file against file rules
	var violations []Violation
	for filePath := range changedFiles {
		namespace := fmt.Sprintf("file:%s", filePath)
		rules := state.FindRulesForNamespace(namespace)

		for _, rule := range rules {
			verifier := NewSignatureVerifier(rule, state)
			err = verifier.Verify(signerKeyIDs)
			if err != nil {
				violations = append(violations, Violation{
					BookmarkName: filePath,
					RuleName:     rule.ID(),
					Message:      fmt.Sprintf("file rule %q for %s: %s", rule.ID(), filePath, err.Error()),
				})
			}
		}
	}

	return violations, nil
}

// VerifyMergeable checks if the feature bookmark can be merged into the target
// bookmark. It verifies that sufficient authorizations exist for the merge.
// Returns (needsRSLSignature, error):
//   - (false, nil): merge allowed, anyone can perform it
//   - (true, nil): merge allowed but must be performed by an authorized principal
//   - (false, err): merge not allowed
func (v *PolicyVerifier) VerifyMergeable(targetBookmark, featureBookmark string) (bool, error) {
	state, err := LoadCurrentState(v.repo)
	if err != nil {
		return false, fmt.Errorf("loading policy: %w", err)
	}

	if state.TargetsMetadata == nil {
		return false, nil // No policy, anyone can merge
	}

	namespace := fmt.Sprintf("bookmark:%s", targetBookmark)
	rules := state.FindRulesForNamespace(namespace)
	if len(rules) == 0 {
		return false, nil // No rules protect target, anyone can merge
	}

	// Find the current state of target and feature bookmarks from the OSL
	targetEntry, err := osl.GetLatestOperationEntryFor(v.repo, targetBookmark)
	var targetID string
	if err == nil {
		for _, delta := range targetEntry.BookmarkDeltas {
			if delta.Name == targetBookmark {
				targetID = delta.ToID
				break
			}
		}
	}

	featureEntry, err := osl.GetLatestOperationEntryFor(v.repo, featureBookmark)
	if err != nil {
		return false, fmt.Errorf("no OSL entry for feature bookmark %q: %w", featureBookmark, err)
	}
	var featureID string
	for _, delta := range featureEntry.BookmarkDeltas {
		if delta.Name == featureBookmark {
			featureID = delta.ToID
			break
		}
	}

	// Load attestations
	currentAttestations, err := attestations.LoadCurrentAttestations(v.repo)
	if err != nil {
		return false, fmt.Errorf("loading attestations: %w", err)
	}

	// Check if there are sufficient attestation signatures for the merge
	// Try to get tree ID for the feature commit
	featureTreeID := featureID
	if h, err := gitinterface.NewHash(featureID); err == nil {
		if treeH, err := v.repo.GetCommitTreeID(h); err == nil {
			featureTreeID = treeH.String()
		}
	}

	authKeyIDs, _ := currentAttestations.GetSignerKeyIDsForAuthorization(
		v.repo, targetBookmark, targetID, featureTreeID)

	// Check each rule
	needsOSLSignature := false
	for _, rule := range rules {
		verifier := NewSignatureVerifier(rule, state)

		// Check if attestation signatures alone meet the threshold
		if len(authKeyIDs) > 0 {
			err := verifier.Verify(authKeyIDs)
			if err == nil {
				continue // This rule is fully satisfied by attestations
			}
		}

		// Attestations alone don't meet the threshold — the OSL entry
		// signer must also be authorized
		if rule.Threshold() == 1 && len(authKeyIDs) == 0 {
			needsOSLSignature = true
			continue
		}

		// For threshold > 1, check if attestations + 1 more signer would suffice
		if len(authKeyIDs)+1 >= rule.Threshold() {
			needsOSLSignature = true
			continue
		}

		return false, fmt.Errorf("%w: insufficient authorizations for rule %q (need %d, have %d attestation signatures)",
			ErrVerificationFailed, rule.ID(), rule.Threshold(), len(authKeyIDs))
	}

	return needsOSLSignature, nil
}

// matchesNamespace checks if a pattern matches a namespace using glob matching.
func matchesNamespace(pattern, namespace string) bool {
	if pattern == namespace {
		return true
	}

	patternParts := strings.SplitN(pattern, ":", 2)
	namespaceParts := strings.SplitN(namespace, ":", 2)

	if len(patternParts) != 2 || len(namespaceParts) != 2 {
		return false
	}

	if patternParts[0] != namespaceParts[0] {
		return false
	}

	matched, err := filepath.Match(patternParts[1], namespaceParts[1])
	if err != nil {
		return false
	}
	return matched
}
