// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package v01

import (
	"encoding/json"
	"testing"

	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
	"github.com/jjtuf/jjtuf/internal/tuf"
)

func TestNewRootMetadata(t *testing.T) {
	root := NewRootMetadata()
	if root == nil {
		t.Fatal("expected non-nil root metadata")
	}
	if root.SchemaVersion() != SchemaVersion {
		t.Errorf("wrong schema version: %s", root.SchemaVersion())
	}
	threshold, err := root.GetRootThreshold()
	if err != nil {
		t.Fatal(err)
	}
	if threshold != 1 {
		t.Errorf("expected default threshold 1, got %d", threshold)
	}
}

func TestAddRootPrincipal(t *testing.T) {
	root := NewRootMetadata()
	key := &common.SSLibKey{KeyID: "key1", KeyType: common.SSHKeyType}
	p := NewPrincipal("alice", []*common.SSLibKey{key})

	if err := root.AddRootPrincipal(p); err != nil {
		t.Fatalf("AddRootPrincipal: %v", err)
	}

	principals, err := root.GetRootPrincipals()
	if err != nil {
		t.Fatal(err)
	}
	if len(principals) != 1 || principals[0].ID() != "alice" {
		t.Error("principal not found after add")
	}
}

func TestAddRootPrincipalDuplicate(t *testing.T) {
	root := NewRootMetadata()
	p := NewPrincipal("alice", nil)
	_ = root.AddRootPrincipal(p)
	_ = root.AddRootPrincipal(p) // should be idempotent

	principals, _ := root.GetRootPrincipals()
	if len(principals) != 1 {
		t.Errorf("expected 1 principal, got %d", len(principals))
	}
}

func TestUpdateRootThreshold(t *testing.T) {
	root := NewRootMetadata()
	p1 := NewPrincipal("alice", nil)
	p2 := NewPrincipal("bob", nil)
	_ = root.AddRootPrincipal(p1)
	_ = root.AddRootPrincipal(p2)

	if err := root.UpdateRootThreshold(2); err != nil {
		t.Fatalf("UpdateRootThreshold(2): %v", err)
	}

	threshold, _ := root.GetRootThreshold()
	if threshold != 2 {
		t.Errorf("expected threshold 2, got %d", threshold)
	}
}

func TestUpdateThresholdExceedsPrincipals(t *testing.T) {
	root := NewRootMetadata()
	p := NewPrincipal("alice", nil)
	_ = root.AddRootPrincipal(p)

	err := root.UpdateRootThreshold(5)
	if err != tuf.ErrCannotMeetThreshold {
		t.Errorf("expected ErrCannotMeetThreshold, got %v", err)
	}
}

func TestAddAndGetGlobalRule(t *testing.T) {
	root := NewRootMetadata()
	rule := &simpleTestGlobalRule{name: "no-force", ruleType: "block-force-pushes", patterns: []string{"bookmark:main"}}

	if err := root.AddGlobalRule(rule); err != nil {
		t.Fatalf("AddGlobalRule: %v", err)
	}

	globalRules := root.GetGlobalRules()
	rules, ok := globalRules["block-force-pushes"]
	if !ok || len(rules) != 1 {
		t.Error("global rule not found after add")
	}
	if rules[0].Name() != "no-force" {
		t.Errorf("wrong rule name: %s", rules[0].Name())
	}
}

func TestAddGlobalRuleDuplicate(t *testing.T) {
	root := NewRootMetadata()
	rule := &simpleTestGlobalRule{name: "dup", ruleType: "block-force-pushes", patterns: nil}
	_ = root.AddGlobalRule(rule)
	err := root.AddGlobalRule(rule)
	if err != tuf.ErrGlobalRuleAlreadyExists {
		t.Errorf("expected ErrGlobalRuleAlreadyExists, got %v", err)
	}
}

func TestDeleteGlobalRule(t *testing.T) {
	root := NewRootMetadata()
	rule := &simpleTestGlobalRule{name: "rule1", ruleType: "block-force-pushes", patterns: nil}
	_ = root.AddGlobalRule(rule)
	if err := root.DeleteGlobalRule("rule1"); err != nil {
		t.Fatalf("DeleteGlobalRule: %v", err)
	}
	if err := root.DeleteGlobalRule("rule1"); err != tuf.ErrGlobalRuleNotFound {
		t.Errorf("expected ErrGlobalRuleNotFound, got %v", err)
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	root := NewRootMetadata()
	_ = root.AddRootPrincipal(NewPrincipal("alice", nil))

	data, err := root.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Verify it's valid JSON
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Round-trip
	restored, err := UnmarshalRootMetadata(data)
	if err != nil {
		t.Fatalf("UnmarshalRootMetadata: %v", err)
	}

	principals, _ := restored.GetRootPrincipals()
	if len(principals) != 1 || principals[0].ID() != "alice" {
		t.Error("principal not preserved through marshal/unmarshal")
	}
}

func TestUnmarshalWrongVersion(t *testing.T) {
	data := []byte(`{"schemaVersion":"https://wrong.version/v99"}`)
	_, err := UnmarshalRootMetadata(data)
	if err == nil {
		t.Error("expected error for wrong schema version")
	}
}

// simpleTestGlobalRule implements tuf.GlobalRule for tests.
type simpleTestGlobalRule struct {
	name, ruleType string
	patterns       []string
}

func (r *simpleTestGlobalRule) Type() string       { return r.ruleType }
func (r *simpleTestGlobalRule) Name() string       { return r.name }
func (r *simpleTestGlobalRule) Patterns() []string { return r.patterns }
