// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package v01

import (
	"testing"

	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
	"github.com/jjtuf/jjtuf/internal/tuf"
)

func TestNewTargetsMetadata(t *testing.T) {
	targets := NewTargetsMetadata()
	if targets == nil {
		t.Fatal("expected non-nil")
	}
	if targets.SchemaVersion() != TargetsSchemaVersion {
		t.Errorf("wrong schema: %s", targets.SchemaVersion())
	}
}

func TestAddAndGetRule(t *testing.T) {
	targets := NewTargetsMetadata()
	key := &common.SSLibKey{KeyID: "k1", KeyType: common.SSHKeyType}
	p := NewPrincipalWithKey("alice", key)
	_ = targets.AddPrincipal(p)

	err := targets.AddRule("protect-main", []string{"alice"}, []string{"bookmark:main"}, 1)
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	rules := targets.GetRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].ID() != "protect-main" {
		t.Errorf("wrong rule name: %s", rules[0].ID())
	}
}

func TestRuleMatches(t *testing.T) {
	targets := NewTargetsMetadata()
	_ = targets.AddPrincipal(NewPrincipal("alice", nil))
	_ = targets.AddRule("glob-rule", []string{"alice"}, []string{"bookmark:release/*"}, 1)

	rules := targets.GetRules()
	rule := rules[0]

	tests := []struct {
		namespace string
		want      bool
	}{
		{"bookmark:release/v1.0", true},
		{"bookmark:release/v2.0-rc1", true},
		{"bookmark:main", false},
		{"file:src/main.go", false},
		{"bookmark:release", false},
	}

	for _, tt := range tests {
		got := rule.Matches(tt.namespace)
		if got != tt.want {
			t.Errorf("Matches(%q) = %v, want %v", tt.namespace, got, tt.want)
		}
	}
}

func TestFileRuleMatches(t *testing.T) {
	targets := NewTargetsMetadata()
	_ = targets.AddPrincipal(NewPrincipal("carol", nil))
	_ = targets.AddRule("protect-crypto", []string{"carol"}, []string{"file:src/crypto/*"}, 1)

	rules := targets.GetRules()
	rule := rules[0]

	if !rule.Matches("file:src/crypto/keys.go") {
		t.Error("expected file rule to match")
	}
	if rule.Matches("file:src/main.go") {
		t.Error("expected file rule not to match")
	}
	if rule.Matches("bookmark:main") {
		t.Error("file rule should not match bookmark namespace")
	}
}

func TestAddRuleDuplicate(t *testing.T) {
	targets := NewTargetsMetadata()
	_ = targets.AddPrincipal(NewPrincipal("alice", nil))
	_ = targets.AddRule("r1", []string{"alice"}, []string{"bookmark:main"}, 1)
	err := targets.AddRule("r1", []string{"alice"}, []string{"bookmark:main"}, 1)
	if err != tuf.ErrDuplicatedRuleName {
		t.Errorf("expected ErrDuplicatedRuleName, got %v", err)
	}
}

func TestAddRuleThresholdExceedsPrincipals(t *testing.T) {
	targets := NewTargetsMetadata()
	_ = targets.AddPrincipal(NewPrincipal("alice", nil))
	err := targets.AddRule("r1", []string{"alice"}, []string{"bookmark:main"}, 5)
	if err != tuf.ErrCannotMeetThreshold {
		t.Errorf("expected ErrCannotMeetThreshold, got %v", err)
	}
}

func TestUpdateRule(t *testing.T) {
	targets := NewTargetsMetadata()
	_ = targets.AddPrincipal(NewPrincipal("alice", nil))
	_ = targets.AddPrincipal(NewPrincipal("bob", nil))
	_ = targets.AddRule("r1", []string{"alice"}, []string{"bookmark:main"}, 1)

	err := targets.UpdateRule("r1", []string{"alice", "bob"}, nil, 2)
	if err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}

	rules := targets.GetRules()
	if rules[0].Threshold() != 2 {
		t.Errorf("expected threshold 2, got %d", rules[0].Threshold())
	}
	if len(rules[0].GetPrincipalIDs()) != 2 {
		t.Errorf("expected 2 principals, got %d", len(rules[0].GetPrincipalIDs()))
	}
}

func TestDeleteRule(t *testing.T) {
	targets := NewTargetsMetadata()
	_ = targets.AddPrincipal(NewPrincipal("alice", nil))
	_ = targets.AddRule("r1", []string{"alice"}, []string{"bookmark:main"}, 1)

	if err := targets.DeleteRule("r1"); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if len(targets.GetRules()) != 0 {
		t.Error("expected 0 rules after delete")
	}
	if err := targets.DeleteRule("r1"); err != tuf.ErrRuleNotFound {
		t.Errorf("expected ErrRuleNotFound, got %v", err)
	}
}

func TestJjtufPrefixProtection(t *testing.T) {
	targets := NewTargetsMetadata()
	err := targets.AddRule("jjtuf-protected", []string{}, []string{"bookmark:main"}, 0)
	if err != tuf.ErrCannotManipulateRulesWithJjtufPrefix {
		t.Errorf("expected jjtuf prefix error, got %v", err)
	}
}

func TestTargetsMarshalUnmarshal(t *testing.T) {
	targets := NewTargetsMetadata()
	_ = targets.AddPrincipal(NewPrincipal("alice", nil))
	_ = targets.AddRule("r1", []string{"alice"}, []string{"bookmark:main"}, 1)

	data, err := targets.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	restored, err := UnmarshalTargetsMetadata(data)
	if err != nil {
		t.Fatalf("UnmarshalTargetsMetadata: %v", err)
	}
	if len(restored.GetRules()) != 1 {
		t.Error("rules not preserved after marshal/unmarshal")
	}
}
