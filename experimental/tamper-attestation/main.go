// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

// Tamper-attestation is an e2e test helper that locates a reference
// authorization blob under refs/jjtuf/attestations and overwrites it with a
// cryptographically-invalid envelope.  It is used to verify that "jjtuf verify"
// rejects a tampered attestation rather than silently accepting it.
//
// Usage:
//
//	go run ./experimental/tamper-attestation /path/to/repo [path-substring]
//
// If a path-substring is supplied, the first blob whose path contains that
// substring is targeted. Without one, the first reference-authorization blob
// in tree-walk order is used; for a single-authorization test repo this is
// fine, but for multi-authorization repos pass a substring to be deterministic.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <repo-path> [path-substring]\n", os.Args[0])
		os.Exit(2)
	}
	repo := os.Args[1]
	pathFilter := ""
	if len(os.Args) == 3 {
		pathFilter = os.Args[2]
	}

	gitDir, err := runGit(repo, "rev-parse", "--git-dir")
	must(err)
	gitDir = strings.TrimSpace(gitDir)

	// Resolve refs/jjtuf/attestations -> tree
	attTreeOut, err := runGit(repo, "rev-parse", "refs/jjtuf/attestations^{tree}")
	must(err)
	attTree := strings.TrimSpace(attTreeOut)

	// List all blobs under the tree
	out, err := runGit(repo, "ls-tree", "-r", attTree)
	must(err)

	var (
		blobID   string
		fullPath string
	)
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		// Format: <mode> <type> <id>\t<path>
		fields := strings.SplitN(line, "\t", 2)
		if len(fields) != 2 {
			continue
		}
		head := strings.Fields(fields[0])
		if len(head) != 3 || head[1] != "blob" {
			continue
		}
		if !strings.HasPrefix(fields[1], "reference-authorizations/") {
			continue
		}
		if pathFilter != "" && !strings.Contains(fields[1], pathFilter) {
			continue
		}
		blobID = head[2]
		fullPath = fields[1]
		break
	}
	if blobID == "" {
		log.Fatal("no reference-authorization blob found under attestations tree")
	}
	fmt.Printf("Tampering: %s (%s)\n", fullPath, short(blobID))

	// Build a forged DSSE envelope.  The signatures here are syntactically
	// well-formed (valid base64) but cryptographically invalid for the payload.
	bad := map[string]any{
		"payloadType": "https://jjtuf.dev/attestations/reference-authorization/v0.1",
		"payload":     base64.StdEncoding.EncodeToString([]byte("malicious-payload")),
		"signatures": []map[string]string{
			{"keyid": "alice", "sig": base64.StdEncoding.EncodeToString([]byte("forged"))},
			{"keyid": "bob", "sig": base64.StdEncoding.EncodeToString([]byte("forged"))},
		},
	}
	badJSON, err := json.Marshal(bad)
	must(err)

	// Write the corrupted envelope as a new blob
	newBlob, err := runGitWithStdin(repo, badJSON, "hash-object", "-w", "--stdin")
	must(err)
	newBlob = strings.TrimSpace(newBlob)
	fmt.Printf("New blob: %s\n", short(newBlob))

	// Walk the tree path and rebuild trees from leaf to root, swapping the blob.
	parts := strings.Split(fullPath, "/")
	if len(parts) < 2 {
		log.Fatal("unexpected path layout: " + fullPath)
	}

	// We rebuild each subtree starting from the directory containing the blob
	// up to the root of the attestations tree.
	currentTree := attTree
	rebuiltID := newBlob // the id we swap in at the leaf
	rebuiltMode := "100644"
	rebuiltType := "blob"

	// Walk parts in REVERSE so we can rebuild bottom-up.
	// e.g., parts = [reference-authorizations, main, -<tree-id>]
	// Step 1: rebuild "main" tree replacing the blob with newBlob.
	// Step 2: rebuild "reference-authorizations" tree replacing "main" with new "main" tree.
	// Step 3: rebuild root tree replacing "reference-authorizations" with new one.
	//
	// To do this cleanly, walk down first to collect each subtree's contents,
	// then rebuild on the way back up.
	type level struct {
		treeID string
		name   string
	}
	descent := []level{{treeID: attTree, name: "<root>"}}
	for i := 0; i < len(parts)-1; i++ {
		p := parts[i]
		sub, err := lookupSubtree(repo, descent[i].treeID, p)
		must(err)
		descent = append(descent, level{treeID: sub, name: p})
	}

	// At the leaf level (parent of blob), the entry name is parts[len-1].
	leafEntry := parts[len(parts)-1]
	currentTree = descent[len(descent)-1].treeID

	for i := len(descent) - 1; i >= 0; i-- {
		entries, err := readTree(repo, descent[i].treeID)
		must(err)
		var entryName string
		if i == len(descent)-1 {
			entryName = leafEntry
		} else {
			entryName = descent[i+1].name
		}

		newEntries := make([]string, 0, len(entries))
		replaced := false
		for _, e := range entries {
			if e.name == entryName {
				newEntries = append(newEntries, fmt.Sprintf("%s %s %s\t%s", rebuiltMode, rebuiltType, rebuiltID, e.name))
				replaced = true
			} else {
				newEntries = append(newEntries, fmt.Sprintf("%s %s %s\t%s", e.mode, e.typ, e.id, e.name))
			}
		}
		if !replaced {
			log.Fatalf("entry %q not found in tree %s", entryName, descent[i].treeID)
		}
		newTree, err := runGitWithStdin(repo, []byte(strings.Join(newEntries, "\n")+"\n"), "mktree")
		must(err)
		rebuiltID = strings.TrimSpace(newTree)
		rebuiltMode = "040000"
		rebuiltType = "tree"
	}
	_ = currentTree

	// Now rebuiltID is the new root tree of refs/jjtuf/attestations.
	parent, err := runGit(repo, "rev-parse", "refs/jjtuf/attestations")
	must(err)
	parent = strings.TrimSpace(parent)

	newCommit, err := runGitWithEnv(repo,
		[]string{"GIT_AUTHOR_NAME=tamper", "GIT_AUTHOR_EMAIL=tamper@local",
			"GIT_COMMITTER_NAME=tamper", "GIT_COMMITTER_EMAIL=tamper@local"},
		"commit-tree", rebuiltID, "-p", parent, "-m", "tamper-test")
	must(err)
	newCommit = strings.TrimSpace(newCommit)

	_, err = runGit(repo, "update-ref", "refs/jjtuf/attestations", newCommit)
	must(err)

	fmt.Printf("Updated refs/jjtuf/attestations -> %s\n", short(newCommit))
	_ = gitDir
}

type treeEntry struct {
	mode, typ, id, name string
}

func readTree(repo, tree string) ([]treeEntry, error) {
	out, err := runGit(repo, "ls-tree", tree)
	if err != nil {
		return nil, err
	}
	var entries []treeEntry
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 2)
		if len(fields) != 2 {
			continue
		}
		head := strings.Fields(fields[0])
		if len(head) != 3 {
			continue
		}
		entries = append(entries, treeEntry{
			mode: head[0], typ: head[1], id: head[2], name: fields[1],
		})
	}
	return entries, nil
}

func lookupSubtree(repo, tree, name string) (string, error) {
	entries, err := readTree(repo, tree)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.name == name {
			if e.typ != "tree" {
				return "", fmt.Errorf("entry %q in %s is not a tree", name, tree)
			}
			return e.id, nil
		}
	}
	return "", fmt.Errorf("entry %q not found in tree %s", name, tree)
}

func runGit(repo string, args ...string) (string, error) {
	return runGitWithEnv(repo, nil, args...)
}

func runGitWithEnv(repo string, extraEnv []string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = repo
	if extraEnv != nil {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("git %s: %s: %w", strings.Join(args, " "), strings.TrimSpace(string(exitErr.Stderr)), err)
		}
		return "", err
	}
	return string(out), nil
}

func runGitWithStdin(repo string, stdin []byte, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = repo
	cmd.Stdin = strings.NewReader(string(stdin))
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("git %s: %s: %w", strings.Join(args, " "), strings.TrimSpace(string(exitErr.Stderr)), err)
		}
		return "", err
	}
	return string(out), nil
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
