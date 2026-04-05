// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

// Package policy implements policy loading, state management, and verification
// for jjtuf. It is the jj-adapted equivalent of gittuf's policy package.
package policy

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jjtuf/jjtuf/internal/signerverifier/dsse"
	"github.com/jjtuf/jjtuf/internal/tuf"
	tufv01 "github.com/jjtuf/jjtuf/internal/tuf/v01"
	"github.com/jjtuf/jjtuf/pkg/gitinterface"
)

const (
	// PolicyRef is the Git reference for active policy metadata.
	PolicyRef = "refs/jjtuf/policy"

	// PolicyStagingRef is the Git reference for staged policy edits.
	PolicyStagingRef = "refs/jjtuf/policy-staging"

	// AttestationsRef is the Git reference for attestations.
	AttestationsRef = "refs/jjtuf/attestations"

	rootMetadataPath    = "root"
	targetsMetadataPath = "targets"
)

var (
	ErrPolicyNotInitialized = errors.New("jjtuf policy not initialized")
	ErrPolicyNotFound       = errors.New("policy metadata not found")
	ErrTargetsNotFound      = errors.New("targets metadata not found")
)

// State represents a loaded policy state at a point in time.
// It contains the root metadata and all rule files applicable at that point.
type State struct {
	// RootMetadata is the root of trust.
	RootMetadata *tufv01.RootMetadata

	// TargetsMetadata is the primary rule file.
	TargetsMetadata *tufv01.TargetsMetadata

	// DelegatedMetadata maps delegation names to their rule files.
	DelegatedMetadata map[string]*tufv01.TargetsMetadata

	// repository is the Git repo for loading additional metadata.
	repository *gitinterface.Repository
}

// LoadCurrentState loads the current active policy from refs/jjtuf/policy.
func LoadCurrentState(repo *gitinterface.Repository) (*State, error) {
	policyTipID, err := repo.GetReference(PolicyRef)
	if err != nil {
		return nil, ErrPolicyNotInitialized
	}

	return LoadStateForEntry(repo, policyTipID)
}

// LoadStateForEntry loads the policy state at a specific Git commit.
func LoadStateForEntry(repo *gitinterface.Repository, entryID gitinterface.Hash) (*State, error) {
	treeID, err := repo.GetCommitTreeID(entryID)
	if err != nil {
		return nil, fmt.Errorf("reading policy commit tree: %w", err)
	}

	state := &State{
		DelegatedMetadata: make(map[string]*tufv01.TargetsMetadata),
		repository:        repo,
	}

	// Load root metadata
	rootBlobID, err := repo.GetPathIDInTree(rootMetadataPath, treeID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrPolicyNotFound, err.Error())
	}

	rootBytes, err := repo.ReadBlob(rootBlobID)
	if err != nil {
		return nil, fmt.Errorf("reading root metadata: %w", err)
	}

	rootMd, err := unmarshalMetadata[tufv01.RootMetadata](rootBytes, tufv01.UnmarshalRootMetadata)
	if err != nil {
		return nil, fmt.Errorf("parsing root metadata: %w", err)
	}
	state.RootMetadata = rootMd

	// Load targets metadata (primary rule file) if it exists
	targetsBlobID, err := repo.GetPathIDInTree(targetsMetadataPath, treeID)
	if err == nil {
		targetsBytes, err := repo.ReadBlob(targetsBlobID)
		if err != nil {
			return nil, fmt.Errorf("reading targets metadata: %w", err)
		}

		targetsMd, err := unmarshalMetadata[tufv01.TargetsMetadata](targetsBytes, tufv01.UnmarshalTargetsMetadata)
		if err != nil {
			return nil, fmt.Errorf("parsing targets metadata: %w", err)
		}
		state.TargetsMetadata = targetsMd
	}

	return state, nil
}

// FindRulesForNamespace returns all rules that match the given namespace.
// Walks the primary rule file and any delegations.
func (s *State) FindRulesForNamespace(namespace string) []tuf.Rule {
	if s.TargetsMetadata == nil {
		return nil
	}

	var matchingRules []tuf.Rule

	for _, rule := range s.TargetsMetadata.GetRules() {
		if rule.Matches(namespace) {
			matchingRules = append(matchingRules, rule)
		}
	}

	// Walk delegations
	for _, delegation := range s.TargetsMetadata.GetDelegations() {
		if delegation.Matches(namespace) {
			delegatedMd, exists := s.DelegatedMetadata[delegation.TargetRuleFile()]
			if exists {
				for _, rule := range delegatedMd.GetRules() {
					if rule.Matches(namespace) {
						matchingRules = append(matchingRules, rule)
					}
				}
			}
		}
		if delegation.IsTerminating() {
			break
		}
	}

	return matchingRules
}

// GetPrincipalByKeyID finds a principal across root and targets metadata by key ID.
func (s *State) GetPrincipalByKeyID(keyID string) (tuf.Principal, bool) {
	// Check root principals
	for _, p := range s.RootMetadata.GetPrincipals() {
		for _, k := range p.Keys() {
			if k.KeyID == keyID {
				return p, true
			}
		}
	}

	// Check targets principals
	if s.TargetsMetadata != nil {
		for _, p := range s.TargetsMetadata.GetPrincipals() {
			for _, k := range p.Keys() {
				if k.KeyID == keyID {
					return p, true
				}
			}
		}
	}

	return nil, false
}

// GetPrincipalByID finds a principal by their ID.
func (s *State) GetPrincipalByID(principalID string) (tuf.Principal, bool) {
	if p, exists := s.RootMetadata.GetPrincipals()[principalID]; exists {
		return p, true
	}
	if s.TargetsMetadata != nil {
		if p, exists := s.TargetsMetadata.GetPrincipals()[principalID]; exists {
			return p, true
		}
	}
	return nil, false
}

// unmarshalMetadata handles DSSE envelope unwrapping or raw JSON parsing.
func unmarshalMetadata[T any](data []byte, parser func([]byte) (*T, error)) (*T, error) {
	// Try DSSE envelope first
	env, err := dsse.Unmarshal(data)
	if err == nil {
		payload, err := env.DecodePayload()
		if err != nil {
			return nil, fmt.Errorf("decoding DSSE payload: %w", err)
		}
		return parser(payload)
	}

	// Fall back to raw JSON
	return parser(data)
}

// ensure json package is importable for future use
var _ = json.Marshal
