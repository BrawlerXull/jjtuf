// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package attestations

import "testing"

func TestNormalizeFromID(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"   ", ""},
		{"0", ""},
		{"00000000", ""},
		{"0000000000000000000000000000000000000000", ""},
		{"  0000000000000000000000000000000000000000  ", ""},
		{"abc123", "abc123"},
		{"  abc123  ", "abc123"},
		{"00000000000000000000000000000000000000a0", "00000000000000000000000000000000000000a0"},
	}

	for _, c := range cases {
		if got := NormalizeFromID(c.in); got != c.want {
			t.Errorf("NormalizeFromID(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestPathSymmetry ensures the storage path produced by every "no parent"
// sentinel is identical, so a writer using one form and a reader using
// another (e.g., the OSL emits "0000…0", the CLI is given "") still hit
// the same envelope.  This was the regression that the independent audit
// caught: the verifier looked up "0000…0-tree" while the storer wrote
// "-tree", silently dropping the attestation from threshold checks.
func TestPathSymmetry_NoParentSentinels(t *testing.T) {
	tree := "deadbeef"
	canonical := ReferenceAuthorizationPath("main", "", tree)

	for _, fromID := range []string{
		"",
		"   ",
		"0",
		"00000000",
		"0000000000000000000000000000000000000000",
	} {
		got := ReferenceAuthorizationPath("main", fromID, tree)
		if got != canonical {
			t.Errorf("ReferenceAuthorizationPath(main, %q, %q) = %q, want %q",
				fromID, tree, got, canonical)
		}

		gotApproval := CodeReviewApprovalPath("main", fromID, tree, "github")
		wantApproval := CodeReviewApprovalPath("main", "", tree, "github")
		if gotApproval != wantApproval {
			t.Errorf("CodeReviewApprovalPath(main, %q, %q, github) = %q, want %q",
				fromID, tree, gotApproval, wantApproval)
		}
	}
}

func TestPathDistinct_NonZeroFromID(t *testing.T) {
	// Two different from-ids must produce different paths.
	a := ReferenceAuthorizationPath("main", "abc", "tree")
	b := ReferenceAuthorizationPath("main", "def", "tree")
	if a == b {
		t.Errorf("expected distinct paths, got %q == %q", a, b)
	}
	// And neither must collide with the no-parent sentinel form.
	canon := ReferenceAuthorizationPath("main", "", "tree")
	if a == canon || b == canon {
		t.Errorf("non-zero fromID collided with no-parent form")
	}
}
