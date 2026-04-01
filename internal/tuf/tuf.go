// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package tuf

import (
	"errors"

	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
)

const (
	// RootRoleName defines the expected name for the jjtuf root of trust.
	RootRoleName = "root"

	// TargetsRoleName defines the expected name for the top level jjtuf policy file.
	TargetsRoleName = "targets"

	// AllowRuleName is the implicit allow rule at the end of delegation chains.
	AllowRuleName = "jjtuf-allow-rule"

	// JjtufPrefix is the reserved prefix for jjtuf-internal rule names.
	JjtufPrefix = "jjtuf-"

	// Global rule types.
	GlobalRuleThresholdType        = "threshold"
	GlobalRuleBlockForcePushesType = "block-force-pushes"
)

var (
	ErrInvalidRootMetadata                      = errors.New("invalid root metadata")
	ErrUnknownRootMetadataVersion               = errors.New("unknown schema version for root metadata")
	ErrUnknownTargetsMetadataVersion            = errors.New("unknown schema version for rule file metadata")
	ErrPrimaryRuleFileInformationNotFoundInRoot = errors.New("root metadata does not contain primary rule file information")
	ErrDuplicatedRuleName                       = errors.New("two rules with same name found in policy")
	ErrInvalidPrincipalID                       = errors.New("principal ID is invalid")
	ErrInvalidPrincipalType                     = errors.New("invalid principal type")
	ErrPrincipalNotFound                        = errors.New("principal not found")
	ErrPrincipalStillInUse                      = errors.New("principal is still in use")
	ErrRuleNotFound                             = errors.New("cannot find rule entry")
	ErrCannotManipulateRulesWithJjtufPrefix     = errors.New("cannot add or change rules whose names have the 'jjtuf-' prefix")
	ErrCannotMeetThreshold                      = errors.New("insufficient keys to meet threshold")
	ErrUnknownGlobalRuleType                    = errors.New("unknown global rule type")
	ErrGlobalRuleNotFound                       = errors.New("global rule not found")
	ErrGlobalRuleAlreadyExists                  = errors.New("global rule already exists")
)

// Principal represents an entity that is granted trust by jjtuf metadata.
// A principal may be a single key, a person (with multiple keys), or a team.
type Principal interface {
	ID() string
	Keys() []*common.SSLibKey
	CustomMetadata() map[string]string
}

// RootMetadata represents the root of trust metadata for jjtuf.
type RootMetadata interface {
	// SetExpires sets the expiry time for the metadata.
	SetExpires(expiry string)

	// SchemaVersion returns the metadata schema version.
	SchemaVersion() string

	// GetRepositoryLocation returns the canonical location of the repository.
	GetRepositoryLocation() string

	// SetRepositoryLocation sets the canonical location.
	SetRepositoryLocation(location string)

	// GetPrincipals returns all principals declared in root metadata.
	GetPrincipals() map[string]Principal

	// AddRootPrincipal adds a principal trusted for root operations.
	AddRootPrincipal(principal Principal) error

	// DeleteRootPrincipal removes a principal from root trust.
	DeleteRootPrincipal(principalID string) error

	// GetRootPrincipals returns principals trusted for root operations.
	GetRootPrincipals() ([]Principal, error)

	// GetRootThreshold returns the threshold for root metadata changes.
	GetRootThreshold() (int, error)

	// UpdateRootThreshold sets a new threshold for root metadata.
	UpdateRootThreshold(threshold int) error

	// AddPrimaryRuleFilePrincipal adds a principal trusted for the primary rule file.
	AddPrimaryRuleFilePrincipal(principal Principal) error

	// DeletePrimaryRuleFilePrincipal removes a principal from primary rule file trust.
	DeletePrimaryRuleFilePrincipal(principalID string) error

	// GetPrimaryRuleFilePrincipals returns principals trusted for the primary rule file.
	GetPrimaryRuleFilePrincipals() ([]Principal, error)

	// GetPrimaryRuleFileThreshold returns the threshold for primary rule file.
	GetPrimaryRuleFileThreshold() (int, error)

	// UpdatePrimaryRuleFileThreshold sets a new threshold for the primary rule file.
	UpdatePrimaryRuleFileThreshold(threshold int) error

	// AddGlobalRule adds a global rule to root metadata.
	AddGlobalRule(rule GlobalRule) error

	// DeleteGlobalRule removes a global rule.
	DeleteGlobalRule(name string) error

	// GetGlobalRules returns all global rules.
	GetGlobalRules() map[string][]GlobalRule
}

// TargetsMetadata represents a rule file in jjtuf policy.
type TargetsMetadata interface {
	// SetExpires sets the expiry time.
	SetExpires(expiry string)

	// SchemaVersion returns the metadata schema version.
	SchemaVersion() string

	// GetPrincipals returns all principals declared in this rule file.
	GetPrincipals() map[string]Principal

	// AddPrincipal adds a principal to this rule file.
	AddPrincipal(principal Principal) error

	// DeletePrincipal removes a principal from this rule file.
	DeletePrincipal(principalID string) error

	// AddRule adds an access control rule.
	AddRule(name string, principals []string, patterns []string, threshold int) error

	// UpdateRule modifies an existing rule.
	UpdateRule(name string, principals []string, patterns []string, threshold int) error

	// DeleteRule removes an access control rule.
	DeleteRule(name string) error

	// GetRules returns all rules in this rule file.
	GetRules() []Rule

	// AddDelegation creates a delegation to another rule file.
	AddDelegation(ruleName string, principals []string, patterns []string, threshold int) error

	// GetDelegations returns all delegations.
	GetDelegations() []Delegation
}

// Rule represents an access control rule in a jjtuf rule file.
type Rule interface {
	// ID returns the rule's name/identifier.
	ID() string

	// Matches returns true if the namespace matches this rule's patterns.
	// Namespaces use the format "bookmark:<name>" or "file:<path>".
	Matches(namespace string) bool

	// Threshold returns the number of signatures required.
	Threshold() int

	// GetPrincipalIDs returns the IDs of principals authorized by this rule.
	GetPrincipalIDs() []string

	// GetPatterns returns the namespace patterns this rule protects.
	GetPatterns() []string

	// IsTerminating returns true if delegation stops at this rule.
	IsTerminating() bool
}

// Delegation represents a delegation to a sub-rule file.
type Delegation interface {
	Rule

	// TargetRuleFile returns the name of the delegated rule file.
	TargetRuleFile() string
}

// GlobalRule represents a repository-wide rule.
type GlobalRule interface {
	// Type returns the global rule type (threshold, block-force-pushes, etc.).
	Type() string

	// Name returns the rule's identifier.
	Name() string

	// Patterns returns the namespace patterns this rule applies to.
	Patterns() []string
}
