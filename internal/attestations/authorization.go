// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package attestations

import (
	"encoding/json"
	"fmt"

	"github.com/jjtuf/jjtuf/internal/signerverifier/dsse"
)

const (
	// ReferenceAuthorizationPredicateType is the in-toto predicate type
	// for jjtuf reference authorization attestations.
	ReferenceAuthorizationPredicateType = "https://jjtuf.dev/attestations/reference-authorization/v0.1"

	// CodeReviewApprovalPredicateType is the in-toto predicate type
	// for code review approval attestations.
	CodeReviewApprovalPredicateType = "https://jjtuf.dev/attestations/code-review-approval/v0.1"
)

// ReferenceAuthorization represents the predicate for authorizing a
// bookmark update. It follows the in-toto attestation format.
type ReferenceAuthorization struct {
	// BookmarkName is the bookmark being updated.
	BookmarkName string `json:"bookmarkName"`

	// FromID is the current commit ID of the bookmark.
	FromID string `json:"fromID"`

	// TargetTreeID is the expected Git tree ID after the update.
	// Using tree ID (not commit ID) allows pre-authorization because
	// the tree can be computed before the commit is created.
	TargetTreeID string `json:"targetTreeID"`
}

// InTotoStatement wraps a predicate in the in-toto statement format.
type InTotoStatement struct {
	Type          string      `json:"_type"`
	PredicateType string      `json:"predicateType"`
	Subject       []Subject   `json:"subject"`
	Predicate     interface{} `json:"predicate"`
}

// Subject identifies what the attestation is about.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest,omitempty"`
}

// NewReferenceAuthorization creates a new reference authorization attestation
// wrapped in an in-toto statement and a DSSE envelope.
func NewReferenceAuthorization(bookmarkName, fromID, targetTreeID string) (*dsse.Envelope, error) {
	auth := &ReferenceAuthorization{
		BookmarkName: bookmarkName,
		FromID:       fromID,
		TargetTreeID: targetTreeID,
	}

	statement := &InTotoStatement{
		Type:          "https://in-toto.io/Statement/v0.1",
		PredicateType: ReferenceAuthorizationPredicateType,
		Subject: []Subject{
			{
				Name: fmt.Sprintf("bookmark:%s", bookmarkName),
				Digest: map[string]string{
					"from":       fromID,
					"targetTree": targetTreeID,
				},
			},
		},
		Predicate: auth,
	}

	statementBytes, err := json.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("serializing authorization: %w", err)
	}

	env := dsse.NewEnvelope(ReferenceAuthorizationPredicateType, statementBytes)
	return env, nil
}

// CodeReviewApproval represents the predicate for a code review approval.
type CodeReviewApproval struct {
	// BookmarkName is the bookmark being updated.
	BookmarkName string `json:"bookmarkName"`

	// FromID is the current commit ID of the bookmark.
	FromID string `json:"fromID"`

	// TargetTreeID is the expected Git tree ID after the update.
	TargetTreeID string `json:"targetTreeID"`

	// System identifies the code review system (e.g., "github", "gerrit").
	System string `json:"system"`

	// ReviewID is the system-specific review identifier (e.g., PR number).
	ReviewID string `json:"reviewID,omitempty"`

	// Approved indicates whether the review was approved or dismissed.
	Approved bool `json:"approved"`
}

// NewCodeReviewApproval creates a new code review approval attestation.
func NewCodeReviewApproval(bookmarkName, fromID, targetTreeID, system, reviewID string, approved bool) (*dsse.Envelope, error) {
	approval := &CodeReviewApproval{
		BookmarkName: bookmarkName,
		FromID:       fromID,
		TargetTreeID: targetTreeID,
		System:       system,
		ReviewID:     reviewID,
		Approved:     approved,
	}

	statement := &InTotoStatement{
		Type:          "https://in-toto.io/Statement/v0.1",
		PredicateType: CodeReviewApprovalPredicateType,
		Subject: []Subject{
			{
				Name: fmt.Sprintf("bookmark:%s", bookmarkName),
				Digest: map[string]string{
					"from":       fromID,
					"targetTree": targetTreeID,
				},
			},
		},
		Predicate: approval,
	}

	statementBytes, err := json.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("serializing approval: %w", err)
	}

	env := dsse.NewEnvelope(CodeReviewApprovalPredicateType, statementBytes)
	return env, nil
}

// ParseReferenceAuthorization extracts the authorization from a DSSE envelope.
func ParseReferenceAuthorization(env *dsse.Envelope) (*ReferenceAuthorization, error) {
	payload, err := env.DecodePayload()
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}

	var statement InTotoStatement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return nil, fmt.Errorf("parsing statement: %w", err)
	}

	if statement.PredicateType != ReferenceAuthorizationPredicateType {
		return nil, fmt.Errorf("unexpected predicate type: %s", statement.PredicateType)
	}

	// Re-marshal and unmarshal the predicate to the concrete type
	predBytes, err := json.Marshal(statement.Predicate)
	if err != nil {
		return nil, err
	}

	var auth ReferenceAuthorization
	if err := json.Unmarshal(predBytes, &auth); err != nil {
		return nil, err
	}

	return &auth, nil
}
