// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"fmt"

	"github.com/jjtuf/jjtuf/internal/tuf"
)

var (
	ErrNoVerifiers              = errors.New("no verifiers present for verification")
	ErrInvalidVerifier          = errors.New("verifier has invalid parameters (is threshold 0?)")
	ErrVerifierConditionsUnmet  = errors.New("verifier's key and threshold constraints not met")
)

// SignatureVerifier checks that a set of signer key IDs satisfies a rule's
// threshold requirements.
type SignatureVerifier struct {
	// Rule is the policy rule being verified.
	Rule tuf.Rule

	// State is the policy state for looking up principals.
	State *State
}

// NewSignatureVerifier creates a verifier for the given rule.
func NewSignatureVerifier(rule tuf.Rule, state *State) *SignatureVerifier {
	return &SignatureVerifier{Rule: rule, State: state}
}

// Verify checks if the given set of signer key IDs satisfies the rule's
// threshold. Returns nil if verification passes.
//
// signerKeyIDs: key IDs extracted from the OSL entry's commit signature
//               and/or attestation signatures.
func (v *SignatureVerifier) Verify(signerKeyIDs []string) error {
	if v.Rule.Threshold() == 0 {
		return ErrInvalidVerifier
	}

	// Map signer key IDs to principal IDs
	authorizedSigners := make(map[string]bool)
	for _, keyID := range signerKeyIDs {
		// Check if this key belongs to an authorized principal
		for _, principalID := range v.Rule.GetPrincipalIDs() {
			principal, found := v.State.GetPrincipalByID(principalID)
			if !found {
				continue
			}

			for _, key := range principal.Keys() {
				if key.KeyID == keyID {
					authorizedSigners[principalID] = true
					break
				}
			}
		}
	}

	// Check threshold
	if len(authorizedSigners) < v.Rule.Threshold() {
		return fmt.Errorf("%w: need %d signatures from authorized principals, got %d",
			ErrVerifierConditionsUnmet, v.Rule.Threshold(), len(authorizedSigners))
	}

	return nil
}

// VerifyPrincipalIDs checks if a set of principal IDs satisfies the rule.
// This is a simpler check when principal IDs are already known (e.g., from
// commit author matching).
func (v *SignatureVerifier) VerifyPrincipalIDs(principalIDs []string) error {
	if v.Rule.Threshold() == 0 {
		return ErrInvalidVerifier
	}

	authorizedCount := 0
	authorizedPrincipals := make(map[string]bool)

	for _, pid := range principalIDs {
		for _, authorizedPID := range v.Rule.GetPrincipalIDs() {
			if pid == authorizedPID && !authorizedPrincipals[pid] {
				authorizedPrincipals[pid] = true
				authorizedCount++
				break
			}
		}
	}

	if authorizedCount < v.Rule.Threshold() {
		return fmt.Errorf("%w: need %d authorized principals, got %d",
			ErrVerifierConditionsUnmet, v.Rule.Threshold(), authorizedCount)
	}

	return nil
}
