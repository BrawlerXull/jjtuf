// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jjtuf/jjtuf/internal/attestations"
	"github.com/jjtuf/jjtuf/internal/osl"
	"github.com/jjtuf/jjtuf/internal/policy"
	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
	"github.com/jjtuf/jjtuf/internal/signerverifier/dsse"
	siged25519 "github.com/jjtuf/jjtuf/internal/signerverifier/ed25519"
	"github.com/jjtuf/jjtuf/internal/signerverifier/loader"
	tufv01 "github.com/jjtuf/jjtuf/internal/tuf/v01"
	"github.com/jjtuf/jjtuf/pkg/gitinterface"
)

func init() {
	dsse.SetDefaultLoader(loader.LoadVerifierFromSSLibKey)
}

// initTestRepo creates a bare git repo in a temp dir and returns a Repository.
func initTestRepo(t *testing.T) *gitinterface.Repository {
	t.Helper()
	dir := t.TempDir()

	// git init --bare
	cmd := exec.Command("git", "init", "--bare", dir)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test",
		"GIT_AUTHOR_EMAIL=test@test.com",
		"GIT_COMMITTER_NAME=Test",
		"GIT_COMMITTER_EMAIL=test@test.com",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}

	// Set git identity config
	for _, args := range [][]string{
		{"config", "user.email", "test@test.com"},
		{"config", "user.name", "Test"},
	} {
		c := exec.Command("git", args...)
		c.Dir = dir
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git config: %v\n%s", err, out)
		}
	}

	repo, err := gitinterface.LoadRepository(dir)
	if err != nil {
		t.Fatalf("LoadRepository: %v", err)
	}
	return repo
}

// makeTestKey generates an Ed25519 key pair and returns a signer and public SSLibKey.
func makeTestKey(t *testing.T) (common.SignerVerifier, *common.SSLibKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sv, err := siged25519.New(priv)
	if err != nil {
		t.Fatalf("siged25519.New: %v", err)
	}
	return sv, sv.Public()
}

// commitPolicy writes root+targets metadata to refs/jjtuf/policy.
func commitPolicy(t *testing.T, repo *gitinterface.Repository, root *tufv01.RootMetadata, targets *tufv01.TargetsMetadata) {
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

	targetsBytes, err := targets.Marshal()
	if err != nil {
		t.Fatalf("marshal targets: %v", err)
	}
	targetsEnv := dsse.NewEnvelope("application/vnd.jjtuf.targets+json", targetsBytes)
	targetsEnvBytes, _ := targetsEnv.Marshal()
	targetsBlobID, err := repo.WriteBlob(targetsEnvBytes)
	if err != nil {
		t.Fatalf("write targets blob: %v", err)
	}

	tb := gitinterface.NewTreeBuilder(repo)
	treeID, err := tb.WriteRootTreeFromBlobIDs(map[string]gitinterface.Hash{
		"root":    rootBlobID,
		"targets": targetsBlobID,
	})
	if err != nil {
		t.Fatalf("write policy tree: %v", err)
	}

	if _, err := repo.Commit(treeID, policy.PolicyRef, "Initialize policy", false); err != nil {
		t.Fatalf("commit policy: %v", err)
	}
}

// createGitCommit creates a real git commit and returns its commit hash.
func createGitCommit(t *testing.T, repo *gitinterface.Repository, ref, content string) gitinterface.Hash {
	t.Helper()

	blobID, err := repo.WriteBlob([]byte(content))
	if err != nil {
		t.Fatalf("WriteBlob: %v", err)
	}

	tb := gitinterface.NewTreeBuilder(repo)
	treeID, err := tb.WriteRootTreeFromBlobIDs(map[string]gitinterface.Hash{
		"README.md": blobID,
	})
	if err != nil {
		t.Fatalf("WriteRootTreeFromBlobIDs: %v", err)
	}

	commitID, err := repo.Commit(treeID, ref, "Add content", false)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return commitID
}

// TestVerifyRefPasses verifies the full pipeline end-to-end:
// policy + attestation + OSL → VerifyRef succeeds.
func TestVerifyRefPasses(t *testing.T) {
	repo := initTestRepo(t)

	// Create alice's key pair
	signer, aliceKey := makeTestKey(t)
	t.Logf("Alice key ID: %s", aliceKey.KeyID)

	// Build policy: root metadata + targets with alice + rule for bookmark:main
	root := tufv01.NewRootMetadata()
	alicePrincipal := tufv01.NewPrincipal("alice", []*common.SSLibKey{aliceKey})
	if err := root.AddRootPrincipal(alicePrincipal); err != nil {
		t.Fatalf("AddRootPrincipal: %v", err)
	}
	if err := root.AddPrimaryRuleFilePrincipal(alicePrincipal); err != nil {
		t.Fatalf("AddPrimaryRuleFilePrincipal: %v", err)
	}

	targets := tufv01.NewTargetsMetadata()
	if err := targets.AddPrincipal(alicePrincipal); err != nil {
		t.Fatalf("targets.AddPrincipal: %v", err)
	}
	if err := targets.AddRule("protect-main", []string{"alice"}, []string{"bookmark:main"}, 1); err != nil {
		t.Fatalf("targets.AddRule: %v", err)
	}

	commitPolicy(t, repo, root, targets)
	t.Log("Policy committed OK")

	// Create a real git commit on refs/heads/main
	commitID := createGitCommit(t, repo, "refs/heads/main", "hello world")
	t.Logf("main commit: %s", commitID.String())

	// Get its tree ID
	treeID, err := repo.GetCommitTreeID(commitID)
	if err != nil {
		t.Fatalf("GetCommitTreeID: %v", err)
	}
	t.Logf("main tree: %s", treeID.String())

	// Create a signed attestation: fromID="", toTreeID=treeID
	env, err := attestations.NewReferenceAuthorization("main", "", treeID.String())
	if err != nil {
		t.Fatalf("NewReferenceAuthorization: %v", err)
	}
	if err := env.Sign(signer); err != nil {
		t.Fatalf("env.Sign: %v", err)
	}
	t.Logf("Attestation signed by key ID: %s", signer.KeyID())

	// Store attestation
	currentAttestations := attestations.NewAttestations()
	if err := currentAttestations.SetReferenceAuthorization(repo, env, "main", "", treeID.String()); err != nil {
		t.Fatalf("SetReferenceAuthorization: %v", err)
	}
	if err := currentAttestations.Commit(repo); err != nil {
		t.Fatalf("attestations.Commit: %v", err)
	}
	t.Log("Attestations committed OK")

	// List stored authorization paths for debugging
	paths := currentAttestations.ListReferenceAuthorizations()
	t.Logf("Stored authorization paths: %v", paths)

	// Verify signature on stored attestation in isolation
	reloaded, err := attestations.LoadCurrentAttestations(repo)
	if err != nil {
		t.Fatalf("LoadCurrentAttestations: %v", err)
	}
	t.Logf("Reloaded authorization paths: %v", reloaded.ListReferenceAuthorizations())

	authEnv, err := reloaded.GetReferenceAuthorizationFor(repo, "main", "", treeID.String())
	if err != nil {
		t.Fatalf("GetReferenceAuthorizationFor: %v", err)
	}
	validIDs, err := authEnv.VerifySignatures([]*common.SSLibKey{aliceKey})
	if err != nil {
		t.Fatalf("VerifySignatures (isolation): %v", err)
	}
	t.Logf("Isolated verification OK: validIDs=%v", validIDs)

	// Create an OSL entry: delta = {Name:"main", FromID:"", ToID:commitID.String()}
	delta := osl.BookmarkDelta{
		Name:   "main",
		FromID: "",
		ToID:   commitID.String(),
	}
	entry := osl.NewOperationEntry("test-op-001", nil, "test-digest", []osl.BookmarkDelta{delta})
	if err := entry.Commit(repo, false); err != nil {
		t.Fatalf("osl.Commit: %v", err)
	}
	t.Logf("OSL entry committed, ToID=%s", delta.ToID)

	// Before calling the full pipeline, replicate what verify.go does:
	// resolve delta.ToID (commitID) → tree ID, then call GetSignerKeyIDsForAuthorization
	reloaded2, _ := attestations.LoadCurrentAttestations(repo)
	t.Logf("Reloaded2 authorization paths: %v", reloaded2.ListReferenceAuthorizations())

	resolvedTreeID, err2 := repo.GetCommitTreeID(commitID)
	if err2 != nil {
		t.Fatalf("GetCommitTreeID(commitID): %v", err2)
	}
	t.Logf("Resolved tree ID from commit: %s", resolvedTreeID.String())

	// Try the lookup with policyKeys
	state2, err2 := policy.LoadCurrentState(repo)
	if err2 != nil {
		t.Fatalf("LoadCurrentState: %v", err2)
	}
	rules := state2.FindRulesForNamespace("bookmark:main")
	t.Logf("Found %d rules for bookmark:main", len(rules))
	for _, rule := range rules {
		t.Logf("  Rule %q principals: %v", rule.ID(), rule.GetPrincipalIDs())
		var policyKeys []*common.SSLibKey
		for _, pid := range rule.GetPrincipalIDs() {
			p, ok := state2.GetPrincipalByID(pid)
			t.Logf("  GetPrincipalByID(%q): found=%v", pid, ok)
			if ok {
				for _, k := range p.Keys() {
					t.Logf("    Key: keyID=%s", k.KeyID)
					policyKeys = append(policyKeys, k)
				}
			}
		}
		t.Logf("  policyKeys count: %d", len(policyKeys))

		authIDs, authErr := reloaded2.GetSignerKeyIDsForAuthorization(
			repo, "main", "", resolvedTreeID.String(), policyKeys)
		t.Logf("  GetSignerKeyIDsForAuthorization result: authIDs=%v, err=%v", authIDs, authErr)
	}

	// Now run the full verification pipeline
	verifier := policy.NewPolicyVerifier(repo)
	result, err := verifier.VerifyRef("main")
	if err != nil {
		t.Fatalf("VerifyRef: %v", err)
	}

	if !result.Passed {
		for _, v := range result.Violations {
			t.Errorf("Violation [%s/%s]: %s", v.BookmarkName, v.RuleName, v.Message)
		}
		t.Fatal("VerifyRef should have passed but got violations")
	}
	t.Log("VerifyRef PASSED")
}

// TestVerifyRefFailsWithNoAttestation ensures that when no attestation exists,
// verification fails for a protected bookmark.
func TestVerifyRefFailsWithNoAttestation(t *testing.T) {
	repo := initTestRepo(t)

	_, aliceKey := makeTestKey(t)

	root := tufv01.NewRootMetadata()
	alicePrincipal := tufv01.NewPrincipal("alice", []*common.SSLibKey{aliceKey})
	_ = root.AddRootPrincipal(alicePrincipal)
	_ = root.AddPrimaryRuleFilePrincipal(alicePrincipal)

	targets := tufv01.NewTargetsMetadata()
	_ = targets.AddPrincipal(alicePrincipal)
	_ = targets.AddRule("protect-main", []string{"alice"}, []string{"bookmark:main"}, 1)

	commitPolicy(t, repo, root, targets)

	// Create commit with no attestation
	commitID := createGitCommit(t, repo, "refs/heads/main", "hello world")

	delta := osl.BookmarkDelta{Name: "main", FromID: "", ToID: commitID.String()}
	entry := osl.NewOperationEntry("test-op-002", nil, "test-digest", []osl.BookmarkDelta{delta})
	if err := entry.Commit(repo, false); err != nil {
		t.Fatalf("osl.Commit: %v", err)
	}

	verifier := policy.NewPolicyVerifier(repo)
	result, err := verifier.VerifyRef("main")
	if err != nil {
		t.Fatalf("VerifyRef: %v", err)
	}

	if result.Passed {
		t.Fatal("VerifyRef should have failed (no attestation) but passed")
	}
	t.Logf("VerifyRef correctly failed: %v", result.Violations)
}

// TestVerifyRefUnprotectedBookmark ensures unprotected bookmarks pass without attestation.
func TestVerifyRefUnprotectedBookmark(t *testing.T) {
	repo := initTestRepo(t)

	_, aliceKey := makeTestKey(t)

	root := tufv01.NewRootMetadata()
	alicePrincipal := tufv01.NewPrincipal("alice", []*common.SSLibKey{aliceKey})
	_ = root.AddRootPrincipal(alicePrincipal)
	_ = root.AddPrimaryRuleFilePrincipal(alicePrincipal)

	// Rule only protects "bookmark:release", NOT "bookmark:feature"
	targets := tufv01.NewTargetsMetadata()
	_ = targets.AddPrincipal(alicePrincipal)
	_ = targets.AddRule("protect-release", []string{"alice"}, []string{"bookmark:release"}, 1)

	commitPolicy(t, repo, root, targets)

	commitID := createGitCommit(t, repo, "refs/heads/feature", "feature content")

	delta := osl.BookmarkDelta{Name: "feature", FromID: "", ToID: commitID.String()}
	entry := osl.NewOperationEntry("test-op-003", nil, "test-digest", []osl.BookmarkDelta{delta})
	if err := entry.Commit(repo, false); err != nil {
		t.Fatalf("osl.Commit: %v", err)
	}

	verifier := policy.NewPolicyVerifier(repo)
	result, err := verifier.VerifyRef("feature")
	if err != nil {
		t.Fatalf("VerifyRef: %v", err)
	}

	if !result.Passed {
		t.Fatalf("unprotected bookmark should pass, got violations: %v", result.Violations)
	}
	t.Log("Unprotected bookmark passed correctly")
}

// TestVerifyRefThreshold2 verifies that threshold=2 requires two different signers.
func TestVerifyRefThreshold2(t *testing.T) {
	repo := initTestRepo(t)

	signer1, key1 := makeTestKey(t)
	signer2, key2 := makeTestKey(t)
	t.Logf("signer1 key ID: %s", key1.KeyID)
	t.Logf("signer2 key ID: %s", key2.KeyID)

	root := tufv01.NewRootMetadata()
	_ = root.AddRootPrincipal(tufv01.NewPrincipal("alice", []*common.SSLibKey{key1}))
	_ = root.AddRootPrincipal(tufv01.NewPrincipal("bob", []*common.SSLibKey{key2}))
	_ = root.AddPrimaryRuleFilePrincipal(tufv01.NewPrincipal("alice", []*common.SSLibKey{key1}))

	targets := tufv01.NewTargetsMetadata()
	_ = targets.AddPrincipal(tufv01.NewPrincipal("alice", []*common.SSLibKey{key1}))
	_ = targets.AddPrincipal(tufv01.NewPrincipal("bob", []*common.SSLibKey{key2}))
	_ = targets.AddRule("protect-main", []string{"alice", "bob"}, []string{"bookmark:main"}, 2)

	commitPolicy(t, repo, root, targets)

	commitID := createGitCommit(t, repo, "refs/heads/main", "hello world")
	treeID, _ := repo.GetCommitTreeID(commitID)

	// Sign with BOTH signers
	env, _ := attestations.NewReferenceAuthorization("main", "", treeID.String())
	_ = env.Sign(signer1)
	_ = env.Sign(signer2)

	currentAttestations := attestations.NewAttestations()
	_ = currentAttestations.SetReferenceAuthorization(repo, env, "main", "", treeID.String())
	_ = currentAttestations.Commit(repo)

	delta := osl.BookmarkDelta{Name: "main", FromID: "", ToID: commitID.String()}
	entry := osl.NewOperationEntry("test-op-004", nil, "test-digest", []osl.BookmarkDelta{delta})
	_ = entry.Commit(repo, false)

	verifier := policy.NewPolicyVerifier(repo)
	result, err := verifier.VerifyRef("main")
	if err != nil {
		t.Fatalf("VerifyRef: %v", err)
	}
	if !result.Passed {
		for _, v := range result.Violations {
			t.Errorf("Violation: %s", v.Message)
		}
		t.Fatal("threshold=2 with 2 signatures should pass")
	}
	t.Log("Threshold=2 with 2 signers passed correctly")

	// Now try with only signer1 — should fail
	repo2 := initTestRepo(t)
	commitPolicy(t, repo2, root, targets)

	commitID2 := createGitCommit(t, repo2, "refs/heads/main", "hello world")
	treeID2, _ := repo2.GetCommitTreeID(commitID2)

	env2, _ := attestations.NewReferenceAuthorization("main", "", treeID2.String())
	_ = env2.Sign(signer1) // only one signer

	atts2 := attestations.NewAttestations()
	_ = atts2.SetReferenceAuthorization(repo2, env2, "main", "", treeID2.String())
	_ = atts2.Commit(repo2)

	delta2 := osl.BookmarkDelta{Name: "main", FromID: "", ToID: commitID2.String()}
	entry2 := osl.NewOperationEntry("test-op-005", nil, "test-digest", []osl.BookmarkDelta{delta2})
	_ = entry2.Commit(repo2, false)

	result2, err := policy.NewPolicyVerifier(repo2).VerifyRef("main")
	if err != nil {
		t.Fatalf("VerifyRef (single-sig): %v", err)
	}
	if result2.Passed {
		t.Fatal("threshold=2 with 1 signature should fail but passed")
	}
	t.Log("Threshold=2 with 1 signer correctly failed")
}

// TestVerifyRefManualTrace is a step-by-step replication of verifyEntry
// to find exactly where the failure occurs.
func TestVerifyRefManualTrace(t *testing.T) {
	repo := initTestRepo(t)
	signer, aliceKey := makeTestKey(t)

	// Build policy
	root := tufv01.NewRootMetadata()
	alicePrincipal := tufv01.NewPrincipal("alice", []*common.SSLibKey{aliceKey})
	_ = root.AddRootPrincipal(alicePrincipal)
	_ = root.AddPrimaryRuleFilePrincipal(alicePrincipal)

	targets := tufv01.NewTargetsMetadata()
	_ = targets.AddPrincipal(alicePrincipal)
	_ = targets.AddRule("protect-main", []string{"alice"}, []string{"bookmark:main"}, 1)
	commitPolicy(t, repo, root, targets)

	commitID := createGitCommit(t, repo, "refs/heads/main", "hello world")
	treeID, _ := repo.GetCommitTreeID(commitID)

	// Create and store attestation
	env, _ := attestations.NewReferenceAuthorization("main", "", treeID.String())
	_ = env.Sign(signer)

	currentAttestations := attestations.NewAttestations()
	_ = currentAttestations.SetReferenceAuthorization(repo, env, "main", "", treeID.String())
	_ = currentAttestations.Commit(repo)

	// Create OSL entry
	delta := osl.BookmarkDelta{Name: "main", FromID: "", ToID: commitID.String()}
	entry := osl.NewOperationEntry("test-op-trace", nil, "test-digest", []osl.BookmarkDelta{delta})
	_ = entry.Commit(repo, false)

	// === Step-by-step replication of verifyEntry ===

	// 1. LoadCurrentState
	state, err := policy.LoadCurrentState(repo)
	if err != nil {
		t.Fatalf("LoadCurrentState: %v", err)
	}

	// 2. FindRulesForNamespace
	namespace := "bookmark:main"
	rules := state.FindRulesForNamespace(namespace)
	t.Logf("Rules for %q: %d", namespace, len(rules))
	if len(rules) == 0 {
		t.Fatal("no rules found — this would cause verify to pass silently")
	}

	// 3. LoadCurrentAttestations
	atts, err := attestations.LoadCurrentAttestations(repo)
	if err != nil {
		t.Fatalf("LoadCurrentAttestations: %v", err)
	}
	t.Logf("Loaded attestations, paths: %v", atts.ListReferenceAuthorizations())

	// 4. For each rule, replicate the policyKeys and GetSignerKeyIDsForAuthorization calls
	//    using the EXACT same code path as verifyEntry
	//
	// delta.ToID is the commit ID from the OSL entry
	// delta.FromID is ""
	deltaToID := delta.ToID
	deltaFromID := delta.FromID

	// Replicate: toTreeID := delta.ToID + try GetCommitTreeID (using NewHash, not raw cast)
	toTreeID := deltaToID
	if commitHash, hashErr := gitinterface.NewHash(deltaToID); hashErr == nil {
		resolvedTree, resolveErr := repo.GetCommitTreeID(commitHash)
		t.Logf("GetCommitTreeID(%q): treeID=%q, err=%v", deltaToID, resolvedTree.String(), resolveErr)
		if resolveErr == nil {
			toTreeID = resolvedTree.String()
		}
	}
	t.Logf("toTreeID used for attestation lookup: %q", toTreeID)
	t.Logf("stored attestation path:              %q", "main/-"+treeID.String())
	t.Logf("expected lookup path:                 %q", "main/"+deltaFromID+"-"+toTreeID)

	for _, rule := range rules {
		t.Logf("Rule: %q, principals: %v, threshold: %d", rule.ID(), rule.GetPrincipalIDs(), rule.Threshold())

		// Gather policyKeys
		var policyKeys []*common.SSLibKey
		for _, pid := range rule.GetPrincipalIDs() {
			p, ok := state.GetPrincipalByID(pid)
			t.Logf("  GetPrincipalByID(%q): found=%v", pid, ok)
			if ok {
				keys := p.Keys()
				t.Logf("  Principal %q has %d keys", pid, len(keys))
				for _, k := range keys {
					t.Logf("    key.KeyID=%q, keytype=%q", k.KeyID, k.KeyType)
					policyKeys = append(policyKeys, k)
				}
			}
		}
		t.Logf("  policyKeys count: %d", len(policyKeys))

		// Call GetSignerKeyIDsForAuthorization exactly as verifyEntry does
		authKeyIDs, authErr := atts.GetSignerKeyIDsForAuthorization(
			repo, "main", deltaFromID, toTreeID, policyKeys)
		t.Logf("  GetSignerKeyIDsForAuthorization: authKeyIDs=%v, err=%v", authKeyIDs, authErr)

		// Build signerKeyIDs
		signerKeyIDs := append([]string(nil), authKeyIDs...)
		t.Logf("  signerKeyIDs: %v", signerKeyIDs)

		// Call SignatureVerifier.Verify
		verifier := policy.NewSignatureVerifier(rule, state)
		verifyErr := verifier.Verify(signerKeyIDs)
		t.Logf("  SignatureVerifier.Verify result: %v", verifyErr)

		// Additionally, check key matching manually
		for _, keyID := range signerKeyIDs {
			for _, pid := range rule.GetPrincipalIDs() {
				p, found := state.GetPrincipalByID(pid)
				if !found {
					t.Logf("  Principal %q not found in state!", pid)
					continue
				}
				for _, k := range p.Keys() {
					t.Logf("  Comparing signerKeyID=%q with principal[%q].KeyID=%q: match=%v",
						keyID, pid, k.KeyID, keyID == k.KeyID)
				}
			}
		}
	}
}

// writeTempKey writes a private key to a temp file and returns its path.
// Kept for reference (not currently used but useful for CLI test scenarios).
func writeTempKey(t *testing.T, dir string, keyPEM []byte) string {
	t.Helper()
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, keyPEM, 0600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	return path
}
