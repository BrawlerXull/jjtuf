// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package v01

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
	"github.com/jjtuf/jjtuf/internal/tuf"
)

const SchemaVersion = "https://jjtuf.dev/policy/root/v0.1"

// RootMetadata implements tuf.RootMetadata for schema v0.1.
type RootMetadata struct {
	SchemaVer          string                       `json:"schemaVersion"`
	Expires            string                       `json:"expires,omitempty"`
	Principals         map[string]*PersonPrincipal  `json:"principals"`
	RootRole           Role                         `json:"rootRole"`
	PrimaryRuleFileRole Role                        `json:"primaryRuleFileRole"`
	RepositoryLocation string                       `json:"repositoryLocation,omitempty"`
	GlobalRulesMap     map[string][]globalRule       `json:"globalRules,omitempty"`
}

// Role defines a trust role with a threshold and authorized principal IDs.
type Role struct {
	PrincipalIDs []string `json:"principalIDs"`
	Threshold    int      `json:"threshold"`
}

// PersonPrincipal implements tuf.Principal for a person or entity.
type PersonPrincipal struct {
	PrincipalID    string            `json:"id"`
	PrincipalKeys  []*common.SSLibKey `json:"keys"`
	PrincipalCustom map[string]string `json:"custom,omitempty"`
}

func (p *PersonPrincipal) ID() string                    { return p.PrincipalID }
func (p *PersonPrincipal) Keys() []*common.SSLibKey      { return p.PrincipalKeys }
func (p *PersonPrincipal) CustomMetadata() map[string]string { return p.PrincipalCustom }

// NewRootMetadata creates a new root metadata with initial configuration.
func NewRootMetadata() *RootMetadata {
	return &RootMetadata{
		SchemaVer:      SchemaVersion,
		Principals:     make(map[string]*PersonPrincipal),
		RootRole:       Role{PrincipalIDs: []string{}, Threshold: 1},
		PrimaryRuleFileRole: Role{PrincipalIDs: []string{}, Threshold: 1},
		GlobalRulesMap: make(map[string][]globalRule),
	}
}

func (r *RootMetadata) SetExpires(expiry string)    { r.Expires = expiry }
func (r *RootMetadata) SchemaVersion() string       { return r.SchemaVer }
func (r *RootMetadata) GetRepositoryLocation() string { return r.RepositoryLocation }
func (r *RootMetadata) SetRepositoryLocation(loc string) { r.RepositoryLocation = loc }

func (r *RootMetadata) GetPrincipals() map[string]tuf.Principal {
	result := make(map[string]tuf.Principal, len(r.Principals))
	for id, p := range r.Principals {
		result[id] = p
	}
	return result
}

func (r *RootMetadata) AddRootPrincipal(principal tuf.Principal) error {
	if err := validatePrincipalID(principal.ID()); err != nil {
		return err
	}

	r.addPrincipal(principal)

	for _, id := range r.RootRole.PrincipalIDs {
		if id == principal.ID() {
			return nil // Already in root role
		}
	}
	r.RootRole.PrincipalIDs = append(r.RootRole.PrincipalIDs, principal.ID())
	return nil
}

func (r *RootMetadata) DeleteRootPrincipal(principalID string) error {
	r.RootRole.PrincipalIDs = removeFromSlice(r.RootRole.PrincipalIDs, principalID)
	r.cleanupPrincipal(principalID)
	return nil
}

func (r *RootMetadata) GetRootPrincipals() ([]tuf.Principal, error) {
	return r.getPrincipalsForRole(r.RootRole)
}

func (r *RootMetadata) GetRootThreshold() (int, error) {
	return r.RootRole.Threshold, nil
}

func (r *RootMetadata) UpdateRootThreshold(threshold int) error {
	if threshold < 1 {
		return fmt.Errorf("threshold must be at least 1")
	}
	if threshold > len(r.RootRole.PrincipalIDs) {
		return tuf.ErrCannotMeetThreshold
	}
	r.RootRole.Threshold = threshold
	return nil
}

func (r *RootMetadata) AddPrimaryRuleFilePrincipal(principal tuf.Principal) error {
	if err := validatePrincipalID(principal.ID()); err != nil {
		return err
	}

	r.addPrincipal(principal)

	for _, id := range r.PrimaryRuleFileRole.PrincipalIDs {
		if id == principal.ID() {
			return nil
		}
	}
	r.PrimaryRuleFileRole.PrincipalIDs = append(r.PrimaryRuleFileRole.PrincipalIDs, principal.ID())
	return nil
}

func (r *RootMetadata) DeletePrimaryRuleFilePrincipal(principalID string) error {
	r.PrimaryRuleFileRole.PrincipalIDs = removeFromSlice(r.PrimaryRuleFileRole.PrincipalIDs, principalID)
	r.cleanupPrincipal(principalID)
	return nil
}

func (r *RootMetadata) GetPrimaryRuleFilePrincipals() ([]tuf.Principal, error) {
	return r.getPrincipalsForRole(r.PrimaryRuleFileRole)
}

func (r *RootMetadata) GetPrimaryRuleFileThreshold() (int, error) {
	return r.PrimaryRuleFileRole.Threshold, nil
}

func (r *RootMetadata) UpdatePrimaryRuleFileThreshold(threshold int) error {
	if threshold < 1 {
		return fmt.Errorf("threshold must be at least 1")
	}
	if threshold > len(r.PrimaryRuleFileRole.PrincipalIDs) {
		return tuf.ErrCannotMeetThreshold
	}
	r.PrimaryRuleFileRole.Threshold = threshold
	return nil
}

func (r *RootMetadata) AddGlobalRule(rule tuf.GlobalRule) error {
	if r.GlobalRulesMap == nil {
		r.GlobalRulesMap = make(map[string][]globalRule)
	}
	ruleType := rule.Type()
	for _, existing := range r.GlobalRulesMap[ruleType] {
		if existing.RuleName == rule.Name() {
			return tuf.ErrGlobalRuleAlreadyExists
		}
	}
	r.GlobalRulesMap[ruleType] = append(r.GlobalRulesMap[ruleType], globalRule{
		RuleName:     rule.Name(),
		RuleType:     rule.Type(),
		RulePatterns: rule.Patterns(),
	})
	return nil
}

func (r *RootMetadata) DeleteGlobalRule(name string) error {
	if r.GlobalRulesMap == nil {
		return tuf.ErrGlobalRuleNotFound
	}
	for ruleType, rules := range r.GlobalRulesMap {
		for i, rule := range rules {
			if rule.RuleName == name {
				r.GlobalRulesMap[ruleType] = append(rules[:i], rules[i+1:]...)
				return nil
			}
		}
	}
	return tuf.ErrGlobalRuleNotFound
}

func (r *RootMetadata) GetGlobalRules() map[string][]tuf.GlobalRule {
	result := make(map[string][]tuf.GlobalRule)
	if r.GlobalRulesMap == nil {
		return result
	}
	for ruleType, rules := range r.GlobalRulesMap {
		for _, rule := range rules {
			result[ruleType] = append(result[ruleType], &rule)
		}
	}
	return result
}

// Marshal serializes the root metadata to JSON.
func (r *RootMetadata) Marshal() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// UnmarshalRootMetadata deserializes root metadata from JSON.
func UnmarshalRootMetadata(data []byte) (*RootMetadata, error) {
	var root RootMetadata
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("%w: %s", tuf.ErrInvalidRootMetadata, err.Error())
	}
	if root.SchemaVer != SchemaVersion {
		return nil, fmt.Errorf("%w: got %s", tuf.ErrUnknownRootMetadataVersion, root.SchemaVer)
	}
	return &root, nil
}

// Helper methods

func (r *RootMetadata) addPrincipal(principal tuf.Principal) {
	if _, exists := r.Principals[principal.ID()]; !exists {
		r.Principals[principal.ID()] = &PersonPrincipal{
			PrincipalID:    principal.ID(),
			PrincipalKeys:  principal.Keys(),
			PrincipalCustom: principal.CustomMetadata(),
		}
	}
}

func (r *RootMetadata) cleanupPrincipal(principalID string) {
	// Only remove from principals map if not referenced by any role
	for _, id := range r.RootRole.PrincipalIDs {
		if id == principalID {
			return
		}
	}
	for _, id := range r.PrimaryRuleFileRole.PrincipalIDs {
		if id == principalID {
			return
		}
	}
	delete(r.Principals, principalID)
}

func (r *RootMetadata) getPrincipalsForRole(role Role) ([]tuf.Principal, error) {
	result := make([]tuf.Principal, 0, len(role.PrincipalIDs))
	for _, id := range role.PrincipalIDs {
		p, exists := r.Principals[id]
		if !exists {
			return nil, fmt.Errorf("%w: %s", tuf.ErrPrincipalNotFound, id)
		}
		result = append(result, p)
	}
	return result, nil
}

func validatePrincipalID(id string) error {
	if id == "" {
		return tuf.ErrInvalidPrincipalID
	}
	if strings.HasPrefix(id, tuf.JjtufPrefix) {
		return fmt.Errorf("%w: IDs with prefix '%s' are reserved", tuf.ErrInvalidPrincipalID, tuf.JjtufPrefix)
	}
	return nil
}

func removeFromSlice(s []string, item string) []string {
	result := make([]string, 0, len(s))
	for _, v := range s {
		if v != item {
			result = append(result, v)
		}
	}
	return result
}

// globalRule implements tuf.GlobalRule.
type globalRule struct {
	RuleName     string   `json:"name"`
	RuleType     string   `json:"type"`
	RulePatterns []string `json:"patterns"`
}

func (g *globalRule) Type() string       { return g.RuleType }
func (g *globalRule) Name() string       { return g.RuleName }
func (g *globalRule) Patterns() []string { return g.RulePatterns }

// Verify interface compliance.
var (
	_ tuf.RootMetadata = (*RootMetadata)(nil)
	_ tuf.Principal    = (*PersonPrincipal)(nil)
	_ tuf.GlobalRule   = (*globalRule)(nil)
)

// NewPrincipal creates a PersonPrincipal from an ID and keys.
func NewPrincipal(id string, keys []*common.SSLibKey) *PersonPrincipal {
	return &PersonPrincipal{
		PrincipalID:   id,
		PrincipalKeys: keys,
	}
}

// init ensures errors implement the correct interface
func init() {
	_ = errors.New("") // ensure errors package is used
}
