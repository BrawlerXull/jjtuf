// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package v01

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
	"github.com/jjtuf/jjtuf/internal/tuf"
)

const TargetsSchemaVersion = "https://jjtuf.dev/policy/targets/v0.1"

// TargetsMetadata implements tuf.TargetsMetadata for schema v0.1.
type TargetsMetadata struct {
	SchemaVer  string                      `json:"schemaVersion"`
	Expires    string                      `json:"expires,omitempty"`
	Principals map[string]*PersonPrincipal `json:"principals"`
	Rules      []*ruleEntry                `json:"rules"`
	Delegations []*delegationEntry         `json:"delegations,omitempty"`
}

// ruleEntry implements tuf.Rule.
type ruleEntry struct {
	RuleName       string   `json:"name"`
	RulePatterns   []string `json:"patterns"`
	RulePrincipals []string `json:"principalIDs"`
	RuleThreshold  int      `json:"threshold"`
	Terminating    bool     `json:"terminating,omitempty"`
}

func (r *ruleEntry) ID() string             { return r.RuleName }
func (r *ruleEntry) Threshold() int         { return r.RuleThreshold }
func (r *ruleEntry) GetPrincipalIDs() []string { return r.RulePrincipals }
func (r *ruleEntry) GetPatterns() []string   { return r.RulePatterns }
func (r *ruleEntry) IsTerminating() bool     { return r.Terminating }

func (r *ruleEntry) Matches(namespace string) bool {
	for _, pattern := range r.RulePatterns {
		if matchPattern(pattern, namespace) {
			return true
		}
	}
	return false
}

// delegationEntry implements tuf.Delegation.
type delegationEntry struct {
	ruleEntry
	TargetFile string `json:"targetRuleFile"`
}

func (d *delegationEntry) TargetRuleFile() string { return d.TargetFile }

// NewTargetsMetadata creates a new targets metadata.
func NewTargetsMetadata() *TargetsMetadata {
	return &TargetsMetadata{
		SchemaVer:  TargetsSchemaVersion,
		Principals: make(map[string]*PersonPrincipal),
		Rules:      []*ruleEntry{},
	}
}

func (t *TargetsMetadata) SetExpires(expiry string) { t.Expires = expiry }
func (t *TargetsMetadata) SchemaVersion() string    { return t.SchemaVer }

func (t *TargetsMetadata) GetPrincipals() map[string]tuf.Principal {
	result := make(map[string]tuf.Principal, len(t.Principals))
	for id, p := range t.Principals {
		result[id] = p
	}
	return result
}

func (t *TargetsMetadata) AddPrincipal(principal tuf.Principal) error {
	if err := validatePrincipalID(principal.ID()); err != nil {
		return err
	}
	t.Principals[principal.ID()] = &PersonPrincipal{
		PrincipalID:    principal.ID(),
		PrincipalKeys:  principal.Keys(),
		PrincipalCustom: principal.CustomMetadata(),
	}
	return nil
}

func (t *TargetsMetadata) DeletePrincipal(principalID string) error {
	// Check if principal is still referenced by any rule
	for _, rule := range t.Rules {
		for _, pid := range rule.RulePrincipals {
			if pid == principalID {
				return tuf.ErrPrincipalStillInUse
			}
		}
	}
	if _, exists := t.Principals[principalID]; !exists {
		return tuf.ErrPrincipalNotFound
	}
	delete(t.Principals, principalID)
	return nil
}

func (t *TargetsMetadata) AddRule(name string, principals []string, patterns []string, threshold int) error {
	if strings.HasPrefix(name, tuf.JjtufPrefix) {
		return tuf.ErrCannotManipulateRulesWithJjtufPrefix
	}

	for _, existing := range t.Rules {
		if existing.RuleName == name {
			return tuf.ErrDuplicatedRuleName
		}
	}

	// Validate principals exist
	for _, pid := range principals {
		if _, exists := t.Principals[pid]; !exists {
			return fmt.Errorf("%w: %s", tuf.ErrPrincipalNotFound, pid)
		}
	}

	if threshold > len(principals) {
		return tuf.ErrCannotMeetThreshold
	}

	t.Rules = append(t.Rules, &ruleEntry{
		RuleName:       name,
		RulePatterns:   patterns,
		RulePrincipals: principals,
		RuleThreshold:  threshold,
	})
	return nil
}

func (t *TargetsMetadata) UpdateRule(name string, principals []string, patterns []string, threshold int) error {
	if strings.HasPrefix(name, tuf.JjtufPrefix) {
		return tuf.ErrCannotManipulateRulesWithJjtufPrefix
	}

	for i, existing := range t.Rules {
		if existing.RuleName == name {
			if principals != nil {
				for _, pid := range principals {
					if _, exists := t.Principals[pid]; !exists {
						return fmt.Errorf("%w: %s", tuf.ErrPrincipalNotFound, pid)
					}
				}
				t.Rules[i].RulePrincipals = principals
			}
			if patterns != nil {
				t.Rules[i].RulePatterns = patterns
			}
			if threshold > 0 {
				effectivePrincipals := t.Rules[i].RulePrincipals
				if threshold > len(effectivePrincipals) {
					return tuf.ErrCannotMeetThreshold
				}
				t.Rules[i].RuleThreshold = threshold
			}
			return nil
		}
	}
	return tuf.ErrRuleNotFound
}

func (t *TargetsMetadata) DeleteRule(name string) error {
	if strings.HasPrefix(name, tuf.JjtufPrefix) {
		return tuf.ErrCannotManipulateRulesWithJjtufPrefix
	}

	for i, existing := range t.Rules {
		if existing.RuleName == name {
			t.Rules = append(t.Rules[:i], t.Rules[i+1:]...)
			return nil
		}
	}
	return tuf.ErrRuleNotFound
}

func (t *TargetsMetadata) GetRules() []tuf.Rule {
	rules := make([]tuf.Rule, len(t.Rules))
	for i, r := range t.Rules {
		rules[i] = r
	}
	return rules
}

func (t *TargetsMetadata) AddDelegation(ruleName string, principals []string, patterns []string, threshold int) error {
	if strings.HasPrefix(ruleName, tuf.JjtufPrefix) {
		return tuf.ErrCannotManipulateRulesWithJjtufPrefix
	}

	for _, pid := range principals {
		if _, exists := t.Principals[pid]; !exists {
			return fmt.Errorf("%w: %s", tuf.ErrPrincipalNotFound, pid)
		}
	}

	t.Delegations = append(t.Delegations, &delegationEntry{
		ruleEntry: ruleEntry{
			RuleName:       ruleName,
			RulePatterns:   patterns,
			RulePrincipals: principals,
			RuleThreshold:  threshold,
		},
		TargetFile: ruleName,
	})
	return nil
}

func (t *TargetsMetadata) GetDelegations() []tuf.Delegation {
	delegations := make([]tuf.Delegation, len(t.Delegations))
	for i, d := range t.Delegations {
		delegations[i] = d
	}
	return delegations
}

// Marshal serializes targets metadata to JSON.
func (t *TargetsMetadata) Marshal() ([]byte, error) {
	return json.MarshalIndent(t, "", "  ")
}

// UnmarshalTargetsMetadata deserializes targets metadata from JSON.
func UnmarshalTargetsMetadata(data []byte) (*TargetsMetadata, error) {
	var targets TargetsMetadata
	if err := json.Unmarshal(data, &targets); err != nil {
		return nil, err
	}
	if targets.SchemaVer != TargetsSchemaVersion {
		return nil, fmt.Errorf("%w: got %s", tuf.ErrUnknownTargetsMetadataVersion, targets.SchemaVer)
	}
	return &targets, nil
}

// matchPattern matches a namespace against a pattern using glob-style matching.
// Namespaces: "bookmark:main", "file:src/crypto/keys.go"
// Patterns: "bookmark:main", "bookmark:release/*", "file:src/crypto/*"
func matchPattern(pattern, namespace string) bool {
	// Exact match
	if pattern == namespace {
		return true
	}

	// Split into scheme and path
	patternParts := strings.SplitN(pattern, ":", 2)
	namespaceParts := strings.SplitN(namespace, ":", 2)

	if len(patternParts) != 2 || len(namespaceParts) != 2 {
		return false
	}

	// Scheme must match
	if patternParts[0] != namespaceParts[0] {
		return false
	}

	// Use filepath.Match for glob matching on the path part
	matched, err := filepath.Match(patternParts[1], namespaceParts[1])
	if err != nil {
		return false
	}
	return matched
}

// Verify interface compliance.
var (
	_ tuf.TargetsMetadata = (*TargetsMetadata)(nil)
	_ tuf.Rule            = (*ruleEntry)(nil)
	_ tuf.Delegation      = (*delegationEntry)(nil)
)

// NewPrincipalWithKey is a helper to create a principal with a single key.
func NewPrincipalWithKey(id string, key *common.SSLibKey) *PersonPrincipal {
	return &PersonPrincipal{
		PrincipalID:   id,
		PrincipalKeys: []*common.SSLibKey{key},
	}
}
