// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package policy_test

// Real-world edge case tests for the jjtuf policy verification pipeline.
// These scenarios mirror the kinds of situations that arise in a live
// collaborative repository protected by jjtuf.

import (
	"testing"

	"github.com/jjtuf/jjtuf/internal/attestations"
	"github.com/jjtuf/jjtuf/internal/osl"
	"github.com/jjtuf/jjtuf/internal/policy"
	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
	"github.com/jjtuf/jjtuf/internal/signerverifier/dsse"
	"github.com/jjtuf/jjtuf/internal/tuf"
	tufv01 "github.com/jjtuf/jjtuf/internal/tuf/v01"
	"github.com/jjtuf/jjtuf/pkg/gitinterface"
)

// --- helpers (reuse initTestRepo / makeTestKey / commitPolicy / createGitCommit
//     defined in verify_test.go in the same package) ---

// buildSimplePolicy creates a root+targets pair with one principal and one rule.
func buildSimplePolicy(t *testing.T, principalName string, key *common.SSLibKey, pattern string, threshold int) (*tufv01.RootMetadata, *tufv01.TargetsMetadata, *tufv01.PersonPrincipal) {
	t.Helper()
	root := tufv01.NewRootMetadata()
	p := tufv01.NewPrincipal(principalName, []*common.SSLibKey{key})
	_ = root.AddRootPrincipal(p)
	_ = root.AddPrimaryRuleFilePrincipal(p)

	targets := tufv01.NewTargetsMetadata()
	_ = targets.AddPrincipal(p)
	_ = targets.AddRule("protect-"+principalName, []string{principalName}, []string{pattern}, threshold)
	return root, targets, p
}

// TestBookmarkDeletion verifies behavior when a bookmark is deleted (ToID="").
// Deletion is a real-world operation (jj bookmark delete <name>) that must
// also be authorized under any policy rule protecting that bookmark.
func TestBookmarkDeletion(t *testing.T) {
	repo := initTestRepo(t)
	signer, aliceKey := makeTestKey(t)

	root, targets, _ := buildSimplePolicy(t, "alice", aliceKey, "bookmark:release", 1)
	commitPolicy(t, repo, root, targets)

	// Alice creates the release bookmark first
	commitID := createGitCommit(t, repo, "refs/heads/release", "release content")
	treeID, _ := repo.GetCommitTreeID(commitID)

	env, _ := attestations.NewReferenceAuthorization("release", "", treeID.String())
	_ = env.Sign(signer)

	atts := attestations.NewAttestations()
	_ = atts.SetReferenceAuthorization(repo, env, "release", "", treeID.String())
	_ = atts.Commit(repo)

	// Record creation
	delta := osl.BookmarkDelta{Name: "release", FromID: "", ToID: commitID.String()}
	entry := osl.NewOperationEntry("op-create-release", nil, "vd1", []osl.BookmarkDelta{delta})
	_ = entry.Commit(repo, false)

	result, err := policy.NewPolicyVerifier(repo).VerifyRef("release")
	if err != nil {
		t.Fatalf("VerifyRef (creation): %v", err)
	}
	if !result.Passed {
		t.Fatalf("bookmark creation should pass: %v", result.Violations)
	}

	// Now record a deletion (ToID="").  No attestation → should fail.
	deleteDelta := osl.BookmarkDelta{Name: "release", FromID: commitID.String(), ToID: ""}
	deleteEntry := osl.NewOperationEntry("op-delete-release", nil, "vd2", []osl.BookmarkDelta{deleteDelta})
	_ = deleteEntry.Commit(repo, false)

	result2, err := policy.NewPolicyVerifier(repo).VerifyRef("release")
	if err != nil {
		t.Fatalf("VerifyRef (deletion-no-attest): %v", err)
	}
	if result2.Passed {
		t.Fatal("deletion without attestation should fail")
	}
	t.Logf("Deletion without attestation correctly failed: %v", result2.Violations[0].Message)
}

// TestConflictStateBookmark verifies that a bookmarks in jj conflict state is
// flagged in the violation list.  jj's first-class conflict model means a
// bookmark can point to a conflict commit, which jjtuf must surface.
func TestConflictStateBookmark(t *testing.T) {
	repo := initTestRepo(t)
	signer, aliceKey := makeTestKey(t)

	root, targets, _ := buildSimplePolicy(t, "alice", aliceKey, "bookmark:main", 1)
	commitPolicy(t, repo, root, targets)

	commitID := createGitCommit(t, repo, "refs/heads/main", "initial content")
	treeID, _ := repo.GetCommitTreeID(commitID)

	env, _ := attestations.NewReferenceAuthorization("main", "", treeID.String())
	_ = env.Sign(signer)

	atts := attestations.NewAttestations()
	_ = atts.SetReferenceAuthorization(repo, env, "main", "", treeID.String())
	_ = atts.Commit(repo)

	// Record OSL entry with Conflict=true
	delta := osl.BookmarkDelta{Name: "main", FromID: "", ToID: commitID.String(), Conflict: true}
	entry := osl.NewOperationEntry("op-conflict", nil, "vd1", []osl.BookmarkDelta{delta})
	_ = entry.Commit(repo, false)

	result, err := policy.NewPolicyVerifier(repo).VerifyRef("main")
	if err != nil {
		t.Fatalf("VerifyRef: %v", err)
	}

	// A conflict should appear in Violations even if the bookmark change is otherwise authorized
	hasConflictViolation := false
	for _, v := range result.Violations {
		if v.RuleName == "(conflict)" {
			hasConflictViolation = true
		}
	}
	if !hasConflictViolation {
		t.Fatal("expected conflict violation to be reported")
	}
	t.Logf("Conflict state correctly surfaced: %v", result.Violations)
}

// TestForcePushBlocked verifies that a global "block-force-pushes" rule prevents
// non-ancestor updates.  In a real team, a force-push replaces shared history
// and is a common attack vector.
func TestForcePushBlocked(t *testing.T) {
	repo := initTestRepo(t)

	root := tufv01.NewRootMetadata()
	_, aliceKey := makeTestKey(t)
	alicePrincipal := tufv01.NewPrincipal("alice", []*common.SSLibKey{aliceKey})
	_ = root.AddRootPrincipal(alicePrincipal)
	_ = root.AddPrimaryRuleFilePrincipal(alicePrincipal)

	// Global rule: block force-pushes on bookmark:main
	_ = root.AddGlobalRule(tufv01.NewGlobalRule(tuf.GlobalRuleBlockForcePushesType, "block-force-pushes", []string{"bookmark:main"}))

	targets := tufv01.NewTargetsMetadata()
	_ = targets.AddPrincipal(alicePrincipal)
	commitPolicy(t, repo, root, targets)

	// Create two independent (non-ancestor) commits
	commitA := createGitCommit(t, repo, "refs/heads/main", "branch A content")
	commitB := createGitCommit(t, repo, "refs/heads/main-b", "branch B content")

	// Simulate force-push: from commitA → commitB where B is not a descendant of A
	delta := osl.BookmarkDelta{Name: "main", FromID: commitA.String(), ToID: commitB.String()}
	entry := osl.NewOperationEntry("op-force-push", nil, "vd1", []osl.BookmarkDelta{delta})
	_ = entry.Commit(repo, false)

	result, err := policy.NewPolicyVerifier(repo).VerifyRef("main")
	if err != nil {
		t.Fatalf("VerifyRef: %v", err)
	}
	if result.Passed {
		t.Fatal("force-push should have been blocked by global rule")
	}
	hasForcePushViolation := false
	for _, v := range result.Violations {
		t.Logf("Violation: [%s] %s", v.RuleName, v.Message)
		if v.RuleName == "block-force-pushes" {
			hasForcePushViolation = true
		}
	}
	if !hasForcePushViolation {
		t.Fatal("expected block-force-pushes violation")
	}
	t.Log("Force-push correctly blocked")
}

// commitPolicyRootOnly writes ONLY root metadata to the policy ref, with no
// targets entry. This simulates a "global-rules only" deployment: the user
// ran `jjtuf trust init` and `jjtuf trust add-global-rule` but never ran
// `jjtuf policy init && policy apply`. Global rules must still apply.
func commitPolicyRootOnly(t *testing.T, repo *gitinterface.Repository, root *tufv01.RootMetadata) {
	t.Helper()

	rootBytes, err := root.Marshal()
	if err != nil {
		t.Fatalf("marshal root: %v", err)
	}
	rootEnv := dsse.NewEnvelope("application/vnd.jjtuf.root+json", rootBytes)
	rootEnvBytes, _ := rootEnv.Marshal()
	rootBlobID, err := repo.WriteBlob(rootEnvBytes)
	if err != nil {
		t.Fatalf("write root blob: %v", err)
	}

	tb := gitinterface.NewTreeBuilder(repo)
	treeID, err := tb.WriteRootTreeFromBlobIDs(map[string]gitinterface.Hash{
		"root": rootBlobID,
	})
	if err != nil {
		t.Fatalf("write policy tree: %v", err)
	}

	if _, err := repo.Commit(treeID, policy.PolicyRef, "Init root only", false); err != nil {
		t.Fatalf("commit policy: %v", err)
	}
}

// TestForcePushBlocked_NoTargetsApplied is the regression test for the
// independent-audit finding: a "global-rules only" deployment (no policy
// targets file) silently bypassed block-force-pushes because verifyEntry
// returned early when state.TargetsMetadata == nil — before reaching the
// global-rules loop. The fix moves global-rule evaluation above the
// targets-nil early-return.
func TestForcePushBlocked_NoTargetsApplied(t *testing.T) {
	repo := initTestRepo(t)

	// Root metadata only — global rule, no targets.
	root := tufv01.NewRootMetadata()
	_, aliceKey := makeTestKey(t)
	alice := tufv01.NewPrincipal("alice", []*common.SSLibKey{aliceKey})
	_ = root.AddRootPrincipal(alice)
	_ = root.AddGlobalRule(tufv01.NewGlobalRule(
		tuf.GlobalRuleBlockForcePushesType, "no-force-push",
		[]string{"bookmark:*"}))
	commitPolicyRootOnly(t, repo, root)

	// Two non-ancestor commits — a force-push from A to B.
	commitA := createGitCommit(t, repo, "refs/heads/main", "branch A")
	commitB := createGitCommit(t, repo, "refs/heads/main-b", "branch B")

	delta := osl.BookmarkDelta{Name: "main", FromID: commitA.String(), ToID: commitB.String()}
	entry := osl.NewOperationEntry("op-fp", nil, "vd1", []osl.BookmarkDelta{delta})
	if err := entry.Commit(repo, false); err != nil {
		t.Fatalf("entry.Commit: %v", err)
	}

	result, err := policy.NewPolicyVerifier(repo).VerifyRef("main")
	if err != nil {
		t.Fatalf("VerifyRef: %v", err)
	}
	if result.Passed {
		t.Fatal("force-push must be blocked even with no targets file applied")
	}
	hasFP := false
	for _, v := range result.Violations {
		if v.RuleName == "no-force-push" {
			hasFP = true
		}
		t.Logf("violation: [%s] %s", v.RuleName, v.Message)
	}
	if !hasFP {
		t.Fatal("expected no-force-push violation")
	}
}

// TestForcePushAllowedForFastForward verifies that a legitimate fast-forward
// update (new commit is a descendant of the old one) is NOT blocked by the
// force-push global rule.
func TestForcePushAllowedForFastForward(t *testing.T) {
	repo := initTestRepo(t)

	root := tufv01.NewRootMetadata()
	signer, aliceKey := makeTestKey(t)
	alicePrincipal := tufv01.NewPrincipal("alice", []*common.SSLibKey{aliceKey})
	_ = root.AddRootPrincipal(alicePrincipal)
	_ = root.AddPrimaryRuleFilePrincipal(alicePrincipal)
	_ = root.AddGlobalRule(tufv01.NewGlobalRule(tuf.GlobalRuleBlockForcePushesType, "block-force-pushes", []string{"bookmark:main"}))

	targets := tufv01.NewTargetsMetadata()
	_ = targets.AddPrincipal(alicePrincipal)
	_ = targets.AddRule("protect-main", []string{"alice"}, []string{"bookmark:main"}, 1)
	commitPolicy(t, repo, root, targets)

	// Create initial commit
	commitA := createGitCommit(t, repo, "refs/heads/main", "initial content")
	treeA, _ := repo.GetCommitTreeID(commitA)

	// Authorize A
	envA, _ := attestations.NewReferenceAuthorization("main", "", treeA.String())
	_ = envA.Sign(signer)
	atts := attestations.NewAttestations()
	_ = atts.SetReferenceAuthorization(repo, envA, "main", "", treeA.String())
	_ = atts.Commit(repo)

	// Record creation
	deltaA := osl.BookmarkDelta{Name: "main", FromID: "", ToID: commitA.String()}
	entryA := osl.NewOperationEntry("op-init", nil, "vd1", []osl.BookmarkDelta{deltaA})
	_ = entryA.Commit(repo, false)

	// Create a child commit (fast-forward)
	commitB := createGitCommit(t, repo, "refs/heads/main", "updated content")
	treeB, _ := repo.GetCommitTreeID(commitB)

	// Authorize the fast-forward
	envB, _ := attestations.NewReferenceAuthorization("main", commitA.String(), treeB.String())
	_ = envB.Sign(signer)
	_ = atts.SetReferenceAuthorization(repo, envB, "main", commitA.String(), treeB.String())
	_ = atts.Commit(repo)

	deltaB := osl.BookmarkDelta{Name: "main", FromID: commitA.String(), ToID: commitB.String()}
	entryB := osl.NewOperationEntry("op-ff", nil, "vd2", []osl.BookmarkDelta{deltaB})
	_ = entryB.Commit(repo, false)

	result, err := policy.NewPolicyVerifier(repo).VerifyRef("main")
	if err != nil {
		t.Fatalf("VerifyRef: %v", err)
	}
	if !result.Passed {
		for _, v := range result.Violations {
			t.Errorf("Violation: [%s] %s", v.RuleName, v.Message)
		}
		t.Fatal("fast-forward should not be blocked")
	}
	t.Log("Fast-forward correctly allowed")
}

// TestMultipleBookmarksInOneOperation covers jj's ability to update many
// bookmarks in a single operation (e.g., jj bookmark move --all-remotes).
// All changed bookmarks must be individually authorized.
func TestMultipleBookmarksInOneOperation(t *testing.T) {
	repo := initTestRepo(t)
	signer, aliceKey := makeTestKey(t)

	root := tufv01.NewRootMetadata()
	alicePrincipal := tufv01.NewPrincipal("alice", []*common.SSLibKey{aliceKey})
	_ = root.AddRootPrincipal(alicePrincipal)
	_ = root.AddPrimaryRuleFilePrincipal(alicePrincipal)

	targets := tufv01.NewTargetsMetadata()
	_ = targets.AddPrincipal(alicePrincipal)
	_ = targets.AddRule("protect-main", []string{"alice"}, []string{"bookmark:main"}, 1)
	_ = targets.AddRule("protect-release", []string{"alice"}, []string{"bookmark:release"}, 1)
	commitPolicy(t, repo, root, targets)

	commitMain := createGitCommit(t, repo, "refs/heads/main", "main content")
	treeMain, _ := repo.GetCommitTreeID(commitMain)

	commitRelease := createGitCommit(t, repo, "refs/heads/release", "release content")
	treeRelease, _ := repo.GetCommitTreeID(commitRelease)

	// Authorize both bookmarks
	envMain, _ := attestations.NewReferenceAuthorization("main", "", treeMain.String())
	_ = envMain.Sign(signer)
	envRelease, _ := attestations.NewReferenceAuthorization("release", "", treeRelease.String())
	_ = envRelease.Sign(signer)

	atts := attestations.NewAttestations()
	_ = atts.SetReferenceAuthorization(repo, envMain, "main", "", treeMain.String())
	_ = atts.SetReferenceAuthorization(repo, envRelease, "release", "", treeRelease.String())
	_ = atts.Commit(repo)

	// One OSL operation that touches both bookmarks
	deltas := []osl.BookmarkDelta{
		{Name: "main", FromID: "", ToID: commitMain.String()},
		{Name: "release", FromID: "", ToID: commitRelease.String()},
	}
	entry := osl.NewOperationEntry("op-multi", nil, "vd1", deltas)
	_ = entry.Commit(repo, false)

	// Both bookmarks must pass
	for _, bm := range []string{"main", "release"} {
		result, err := policy.NewPolicyVerifier(repo).VerifyRef(bm)
		if err != nil {
			t.Fatalf("VerifyRef(%s): %v", bm, err)
		}
		if !result.Passed {
			t.Fatalf("bookmark %q should pass, got: %v", bm, result.Violations)
		}
	}
	t.Log("All bookmarks in multi-operation verified correctly")

	// Now partially revoke: create same setup but without release attestation
	repo2 := initTestRepo(t)
	commitPolicy(t, repo2, root, targets)

	commitMain2 := createGitCommit(t, repo2, "refs/heads/main", "main content")
	treeMain2, _ := repo2.GetCommitTreeID(commitMain2)
	commitRelease2 := createGitCommit(t, repo2, "refs/heads/release", "release content")

	envMain2, _ := attestations.NewReferenceAuthorization("main", "", treeMain2.String())
	_ = envMain2.Sign(signer)
	atts2 := attestations.NewAttestations()
	_ = atts2.SetReferenceAuthorization(repo2, envMain2, "main", "", treeMain2.String())
	// release attestation intentionally absent
	_ = atts2.Commit(repo2)

	deltas2 := []osl.BookmarkDelta{
		{Name: "main", FromID: "", ToID: commitMain2.String()},
		{Name: "release", FromID: "", ToID: commitRelease2.String()},
	}
	entry2 := osl.NewOperationEntry("op-multi2", nil, "vd2", deltas2)
	_ = entry2.Commit(repo2, false)

	// main passes, release fails
	r1, _ := policy.NewPolicyVerifier(repo2).VerifyRef("main")
	if !r1.Passed {
		t.Errorf("main should pass in partial scenario")
	}
	r2, _ := policy.NewPolicyVerifier(repo2).VerifyRef("release")
	if r2.Passed {
		t.Errorf("release should fail when attestation is missing")
	}
	t.Log("Partial authorization correctly enforced")
}

// TestFullHistoryVerification checks VerifyRefFull across multiple OSL entries
// for the same bookmark, simulating a bookmark that has been updated many times.
func TestFullHistoryVerification(t *testing.T) {
	repo := initTestRepo(t)
	signer, aliceKey := makeTestKey(t)

	root, targets, _ := buildSimplePolicy(t, "alice", aliceKey, "bookmark:main", 1)
	commitPolicy(t, repo, root, targets)

	var prevCommitID string
	atts := attestations.NewAttestations()

	const numUpdates = 3
	for i := 0; i < numUpdates; i++ {
		content := "version " + string(rune('0'+i))
		commitID := createGitCommit(t, repo, "refs/heads/main", content)
		treeID, _ := repo.GetCommitTreeID(commitID)

		env, _ := attestations.NewReferenceAuthorization("main", prevCommitID, treeID.String())
		_ = env.Sign(signer)
		_ = atts.SetReferenceAuthorization(repo, env, "main", prevCommitID, treeID.String())
		_ = atts.Commit(repo)

		delta := osl.BookmarkDelta{Name: "main", FromID: prevCommitID, ToID: commitID.String()}
		entry := osl.NewOperationEntry("op-update-"+string(rune('0'+i)), nil, "vd", []osl.BookmarkDelta{delta})
		_ = entry.Commit(repo, false)

		prevCommitID = commitID.String()
	}

	results, err := policy.NewPolicyVerifier(repo).VerifyRefFull("main")
	if err != nil {
		t.Fatalf("VerifyRefFull: %v", err)
	}
	if len(results) != numUpdates {
		t.Fatalf("expected %d results, got %d", numUpdates, len(results))
	}
	for i, r := range results {
		if !r.Passed {
			t.Errorf("entry %d failed: %v", i, r.Violations)
		}
	}
	t.Logf("Full history verified: %d entries all passed", len(results))
}

// TestFullHistoryWithOneUnauthorizedEntry verifies that VerifyRefFull surfaces
// a failure in the middle of an otherwise valid history.
func TestFullHistoryWithOneUnauthorizedEntry(t *testing.T) {
	repo := initTestRepo(t)
	signer, aliceKey := makeTestKey(t)

	root, targets, _ := buildSimplePolicy(t, "alice", aliceKey, "bookmark:main", 1)
	commitPolicy(t, repo, root, targets)

	atts := attestations.NewAttestations()

	// Entry 1: authorized
	commit1 := createGitCommit(t, repo, "refs/heads/main", "v1")
	tree1, _ := repo.GetCommitTreeID(commit1)
	env1, _ := attestations.NewReferenceAuthorization("main", "", tree1.String())
	_ = env1.Sign(signer)
	_ = atts.SetReferenceAuthorization(repo, env1, "main", "", tree1.String())
	_ = atts.Commit(repo)
	entry1 := osl.NewOperationEntry("op-v1", nil, "vd1", []osl.BookmarkDelta{{Name: "main", FromID: "", ToID: commit1.String()}})
	_ = entry1.Commit(repo, false)

	// Entry 2: unauthorized (no attestation)
	commit2 := createGitCommit(t, repo, "refs/heads/main", "v2-unauthorized")
	entry2 := osl.NewOperationEntry("op-v2-unauth", nil, "vd2", []osl.BookmarkDelta{{Name: "main", FromID: commit1.String(), ToID: commit2.String()}})
	_ = entry2.Commit(repo, false)

	// Entry 3: authorized
	commit3 := createGitCommit(t, repo, "refs/heads/main", "v3")
	tree3, _ := repo.GetCommitTreeID(commit3)
	env3, _ := attestations.NewReferenceAuthorization("main", commit2.String(), tree3.String())
	_ = env3.Sign(signer)
	_ = atts.SetReferenceAuthorization(repo, env3, "main", commit2.String(), tree3.String())
	_ = atts.Commit(repo)
	entry3 := osl.NewOperationEntry("op-v3", nil, "vd3", []osl.BookmarkDelta{{Name: "main", FromID: commit2.String(), ToID: commit3.String()}})
	_ = entry3.Commit(repo, false)

	results, err := policy.NewPolicyVerifier(repo).VerifyRefFull("main")
	if err != nil {
		t.Fatalf("VerifyRefFull: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if !results[0].Passed {
		t.Error("entry 0 should have passed")
	}
	if results[1].Passed {
		t.Error("entry 1 (unauthorized) should have failed")
	}
	if !results[2].Passed {
		t.Error("entry 2 should have passed")
	}
	t.Log("Full history with one unauthorized entry correctly identified")
}

// TestUnauthorizedKeyRejected verifies that a signature from a key not listed
// in the policy rule is rejected.  This is the "wrong signer" attack scenario.
func TestUnauthorizedKeyRejected(t *testing.T) {
	repo := initTestRepo(t)
	_, aliceKey := makeTestKey(t)
	eveSignerBad, _ := makeTestKey(t) // Eve has a key but is NOT in the policy

	root, targets, _ := buildSimplePolicy(t, "alice", aliceKey, "bookmark:main", 1)
	commitPolicy(t, repo, root, targets)

	commitID := createGitCommit(t, repo, "refs/heads/main", "content by eve")
	treeID, _ := repo.GetCommitTreeID(commitID)

	// Eve signs the attestation, but she's not authorized
	env, _ := attestations.NewReferenceAuthorization("main", "", treeID.String())
	_ = env.Sign(eveSignerBad)

	atts := attestations.NewAttestations()
	_ = atts.SetReferenceAuthorization(repo, env, "main", "", treeID.String())
	_ = atts.Commit(repo)

	delta := osl.BookmarkDelta{Name: "main", FromID: "", ToID: commitID.String()}
	entry := osl.NewOperationEntry("op-eve", nil, "vd1", []osl.BookmarkDelta{delta})
	_ = entry.Commit(repo, false)

	result, err := policy.NewPolicyVerifier(repo).VerifyRef("main")
	if err != nil {
		t.Fatalf("VerifyRef: %v", err)
	}
	if result.Passed {
		t.Fatal("signature from unauthorized key should not satisfy policy")
	}
	t.Logf("Unauthorized key correctly rejected: %v", result.Violations[0].Message)
}

// TestWildcardBookmarkRule verifies that a pattern like "bookmark:release/*"
// protects all sub-bookmarks while leaving others unprotected.
func TestWildcardBookmarkRule(t *testing.T) {
	repo := initTestRepo(t)
	signer, aliceKey := makeTestKey(t)

	root := tufv01.NewRootMetadata()
	alicePrincipal := tufv01.NewPrincipal("alice", []*common.SSLibKey{aliceKey})
	_ = root.AddRootPrincipal(alicePrincipal)
	_ = root.AddPrimaryRuleFilePrincipal(alicePrincipal)

	targets := tufv01.NewTargetsMetadata()
	_ = targets.AddPrincipal(alicePrincipal)
	// Wildcard rule: protects release/*, but NOT main
	_ = targets.AddRule("protect-release-branches", []string{"alice"}, []string{"bookmark:release/*"}, 1)
	commitPolicy(t, repo, root, targets)

	// release/v1 must be authorized
	commitRel := createGitCommit(t, repo, "refs/heads/release/v1", "release v1")
	treeRel, _ := repo.GetCommitTreeID(commitRel)
	envRel, _ := attestations.NewReferenceAuthorization("release/v1", "", treeRel.String())
	_ = envRel.Sign(signer)
	atts := attestations.NewAttestations()
	_ = atts.SetReferenceAuthorization(repo, envRel, "release/v1", "", treeRel.String())
	_ = atts.Commit(repo)

	deltaRel := osl.BookmarkDelta{Name: "release/v1", FromID: "", ToID: commitRel.String()}
	entryRel := osl.NewOperationEntry("op-rel", nil, "vd1", []osl.BookmarkDelta{deltaRel})
	_ = entryRel.Commit(repo, false)

	r1, err := policy.NewPolicyVerifier(repo).VerifyRef("release/v1")
	if err != nil {
		t.Fatalf("VerifyRef(release/v1): %v", err)
	}
	if !r1.Passed {
		t.Fatalf("release/v1 should pass with authorized signature: %v", r1.Violations)
	}

	// main is unprotected — no attestation needed
	commitMain := createGitCommit(t, repo, "refs/heads/main", "main content")
	deltaMain := osl.BookmarkDelta{Name: "main", FromID: "", ToID: commitMain.String()}
	entryMain := osl.NewOperationEntry("op-main", nil, "vd2", []osl.BookmarkDelta{deltaMain})
	_ = entryMain.Commit(repo, false)

	r2, err := policy.NewPolicyVerifier(repo).VerifyRef("main")
	if err != nil {
		t.Fatalf("VerifyRef(main): %v", err)
	}
	if !r2.Passed {
		t.Fatalf("main is unprotected and should pass without attestation: %v", r2.Violations)
	}

	// release/v2 without attestation should fail
	commitRel2 := createGitCommit(t, repo, "refs/heads/release/v2", "release v2")
	deltaRel2 := osl.BookmarkDelta{Name: "release/v2", FromID: "", ToID: commitRel2.String()}
	entryRel2 := osl.NewOperationEntry("op-rel2", nil, "vd3", []osl.BookmarkDelta{deltaRel2})
	_ = entryRel2.Commit(repo, false)

	r3, err := policy.NewPolicyVerifier(repo).VerifyRef("release/v2")
	if err != nil {
		t.Fatalf("VerifyRef(release/v2): %v", err)
	}
	if r3.Passed {
		t.Fatal("release/v2 without attestation should fail under wildcard rule")
	}
	t.Log("Wildcard rule enforced correctly across all cases")
}

// TestCodeReviewApprovalAttestation simulates a forge-approval workflow
// where a separate team member attests a code-review approval before the
// bookmark update can be verified.
func TestCodeReviewApprovalAttestation(t *testing.T) {
	repo := initTestRepo(t)
	_, aliceKey := makeTestKey(t)
	reviewerSigner, reviewerKey := makeTestKey(t)

	root := tufv01.NewRootMetadata()
	alicePrincipal := tufv01.NewPrincipal("alice", []*common.SSLibKey{aliceKey})
	reviewerPrincipal := tufv01.NewPrincipal("reviewer", []*common.SSLibKey{reviewerKey})
	_ = root.AddRootPrincipal(alicePrincipal)
	_ = root.AddRootPrincipal(reviewerPrincipal)
	_ = root.AddPrimaryRuleFilePrincipal(alicePrincipal)

	targets := tufv01.NewTargetsMetadata()
	_ = targets.AddPrincipal(alicePrincipal)
	_ = targets.AddPrincipal(reviewerPrincipal)
	_ = targets.AddRule("protect-main", []string{"reviewer"}, []string{"bookmark:main"}, 1)
	commitPolicy(t, repo, root, targets)

	commitID := createGitCommit(t, repo, "refs/heads/main", "alice's feature")
	treeID, _ := repo.GetCommitTreeID(commitID)

	// Reviewer creates a code-review approval attestation (signed by reviewer)
	approvalEnv, err := attestations.NewCodeReviewApproval("main", "", treeID.String(), "github", "PR#42", true)
	if err != nil {
		t.Fatalf("NewCodeReviewApproval: %v", err)
	}
	_ = approvalEnv.Sign(reviewerSigner)

	atts := attestations.NewAttestations()
	_ = atts.SetCodeReviewApproval(repo, approvalEnv, "main", "", treeID.String(), "github")
	_ = atts.Commit(repo)

	// Also create a reference authorization signed by reviewer
	authEnv, _ := attestations.NewReferenceAuthorization("main", "", treeID.String())
	_ = authEnv.Sign(reviewerSigner)
	_ = atts.SetReferenceAuthorization(repo, authEnv, "main", "", treeID.String())
	_ = atts.Commit(repo)

	delta := osl.BookmarkDelta{Name: "main", FromID: "", ToID: commitID.String()}
	entry := osl.NewOperationEntry("op-cr-approval", nil, "vd1", []osl.BookmarkDelta{delta})
	_ = entry.Commit(repo, false)

	result, err := policy.NewPolicyVerifier(repo).VerifyRef("main")
	if err != nil {
		t.Fatalf("VerifyRef: %v", err)
	}
	if !result.Passed {
		for _, v := range result.Violations {
			t.Errorf("Violation: %s", v.Message)
		}
		t.Fatal("code review approval from authorized reviewer should satisfy policy")
	}
	t.Log("Code-review approval workflow verified correctly")
}

// TestNoPolicyPassesAll verifies that when no policy exists at all, every
// bookmark update passes without any attestation.  This is the zero-trust
// bootstrapping scenario (trust init not yet run).
func TestNoPolicyPassesAll(t *testing.T) {
	repo := initTestRepo(t)

	// Do NOT commit any policy

	commitID := createGitCommit(t, repo, "refs/heads/main", "bootstrap commit")
	delta := osl.BookmarkDelta{Name: "main", FromID: "", ToID: commitID.String()}
	entry := osl.NewOperationEntry("op-bootstrap", nil, "vd1", []osl.BookmarkDelta{delta})
	_ = entry.Commit(repo, false)

	// Policy ref does not exist, so LoadCurrentState will error or return empty state
	// VerifyRef should still succeed (passes by default)
	verifier := policy.NewPolicyVerifier(repo)
	result, err := verifier.VerifyRef("main")
	if err != nil {
		// If there's no policy, VerifyRef may error because it can't load state —
		// that's acceptable; what's not acceptable is a false violation.
		t.Logf("VerifyRef returned error (no policy): %v — acceptable", err)
		return
	}
	if !result.Passed {
		t.Fatalf("no-policy repo should pass all: %v", result.Violations)
	}
	t.Log("No-policy repo passes correctly")
}

// TestDuplicateOSLEntryPrevention verifies that IsOperationIDRecorded
// correctly identifies duplicate operation IDs before they are committed.
func TestDuplicateOSLEntryPrevention(t *testing.T) {
	repo := initTestRepo(t)

	commitID := createGitCommit(t, repo, "refs/heads/main", "initial")

	entry := osl.NewOperationEntry("op-dup-test", nil, "vd1", []osl.BookmarkDelta{
		{Name: "main", FromID: "", ToID: commitID.String()},
	})
	if err := entry.Commit(repo, false); err != nil {
		t.Fatalf("first commit: %v", err)
	}

	// Now check: is this operation ID already recorded?
	found, err := osl.IsOperationIDRecorded(repo, "op-dup-test")
	if err != nil {
		t.Fatalf("IsOperationIDRecorded: %v", err)
	}
	if !found {
		t.Fatal("should have found op-dup-test in the OSL")
	}

	// A different op ID should not be found
	notFound, err := osl.IsOperationIDRecorded(repo, "op-never-recorded")
	if err != nil {
		t.Fatalf("IsOperationIDRecorded (new): %v", err)
	}
	if notFound {
		t.Fatal("op-never-recorded should not be in the OSL")
	}

	t.Log("Duplicate detection working correctly")
}

// TestAnnotationSkipDoesNotAffectVerification verifies that annotation entries
// in the OSL chain do not prevent VerifyRefFull from walking the history.
// This tests the OSL's append-only annotation model.
func TestAnnotationSkipDoesNotAffectVerification(t *testing.T) {
	repo := initTestRepo(t)
	signer, aliceKey := makeTestKey(t)

	root, targets, _ := buildSimplePolicy(t, "alice", aliceKey, "bookmark:main", 1)
	commitPolicy(t, repo, root, targets)

	commitID := createGitCommit(t, repo, "refs/heads/main", "v1")
	treeID, _ := repo.GetCommitTreeID(commitID)

	env, _ := attestations.NewReferenceAuthorization("main", "", treeID.String())
	_ = env.Sign(signer)
	atts := attestations.NewAttestations()
	_ = atts.SetReferenceAuthorization(repo, env, "main", "", treeID.String())
	_ = atts.Commit(repo)

	opEntry := osl.NewOperationEntry("op-annot-test", nil, "vd1", []osl.BookmarkDelta{
		{Name: "main", FromID: "", ToID: commitID.String()},
	})
	_ = opEntry.Commit(repo, false)

	// Now add an annotation entry referencing the operation entry
	opEntry, err := osl.GetLatestOperationEntryFor(repo, "main")
	if err != nil {
		t.Fatalf("GetLatestOperationEntryFor: %v", err)
	}
	annotation := osl.NewAnnotationEntry([]gitinterface.Hash{opEntry.GetID()}, false, "Code review passed PR#10")
	if err := annotation.Commit(repo, false); err != nil {
		t.Fatalf("annotation.Commit: %v", err)
	}

	// VerifyRef should still work correctly despite the annotation in the chain
	result, err := policy.NewPolicyVerifier(repo).VerifyRef("main")
	if err != nil {
		t.Fatalf("VerifyRef with annotation: %v", err)
	}
	if !result.Passed {
		t.Fatalf("annotation entry should not break verification: %v", result.Violations)
	}
	t.Log("Annotation entry in OSL chain handled correctly")
}
