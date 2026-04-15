// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package attestations

import (
	"encoding/json"
	"testing"
)

func TestNewReferenceAuthorization(t *testing.T) {
	env, err := NewReferenceAuthorization("main", "fromID123", "toTreeID456")
	if err != nil {
		t.Fatalf("NewReferenceAuthorization: %v", err)
	}

	if env.PayloadType != ReferenceAuthorizationPredicateType {
		t.Errorf("wrong payload type: %s", env.PayloadType)
	}

	payload, err := env.DecodePayload()
	if err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}

	var stmt InTotoStatement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		t.Fatalf("unmarshal statement: %v", err)
	}

	if stmt.PredicateType != ReferenceAuthorizationPredicateType {
		t.Errorf("wrong predicate type: %s", stmt.PredicateType)
	}
	if len(stmt.Subject) != 1 || stmt.Subject[0].Name != "bookmark:main" {
		t.Errorf("wrong subject: %v", stmt.Subject)
	}
}

func TestParseReferenceAuthorization(t *testing.T) {
	env, _ := NewReferenceAuthorization("main", "from111", "toTree222")

	auth, err := ParseReferenceAuthorization(env)
	if err != nil {
		t.Fatalf("ParseReferenceAuthorization: %v", err)
	}

	if auth.BookmarkName != "main" {
		t.Errorf("wrong bookmark name: %s", auth.BookmarkName)
	}
	if auth.FromID != "from111" {
		t.Errorf("wrong from ID: %s", auth.FromID)
	}
	if auth.TargetTreeID != "toTree222" {
		t.Errorf("wrong target tree ID: %s", auth.TargetTreeID)
	}
}

func TestNewCodeReviewApproval(t *testing.T) {
	env, err := NewCodeReviewApproval("main", "from", "tree", "github", "PR-42", true)
	if err != nil {
		t.Fatalf("NewCodeReviewApproval: %v", err)
	}

	if env.PayloadType != CodeReviewApprovalPredicateType {
		t.Errorf("wrong payload type: %s", env.PayloadType)
	}

	payload, _ := env.DecodePayload()
	var stmt InTotoStatement
	_ = json.Unmarshal(payload, &stmt)

	predBytes, _ := json.Marshal(stmt.Predicate)
	var approval CodeReviewApproval
	_ = json.Unmarshal(predBytes, &approval)

	if approval.System != "github" {
		t.Errorf("wrong system: %s", approval.System)
	}
	if approval.ReviewID != "PR-42" {
		t.Errorf("wrong review ID: %s", approval.ReviewID)
	}
	if !approval.Approved {
		t.Error("expected approved=true")
	}
}

func TestEnvelopeSignature(t *testing.T) {
	env, _ := NewReferenceAuthorization("main", "from", "to")
	env.AddSignature("key-alice", []byte("sig-data"))

	keyIDs := env.GetSignerKeyIDs()
	if len(keyIDs) != 1 || keyIDs[0] != "key-alice" {
		t.Errorf("wrong signer key IDs: %v", keyIDs)
	}
}

func TestReferenceAuthorizationPath(t *testing.T) {
	path := ReferenceAuthorizationPath("main", "fromID", "toTreeID")
	expected := "main/fromID-toTreeID"
	if path != expected {
		t.Errorf("wrong path: got %q, want %q", path, expected)
	}
}

func TestCodeReviewApprovalPath(t *testing.T) {
	path := CodeReviewApprovalPath("release/v1.0", "from", "tree", "github")
	expected := "release/v1.0/from-tree/github"
	if path != expected {
		t.Errorf("wrong path: got %q, want %q", path, expected)
	}
}
