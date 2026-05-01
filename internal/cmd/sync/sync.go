// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package sync

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jjtuf/jjtuf/internal/attestations"
	"github.com/jjtuf/jjtuf/internal/jjinterface"
	"github.com/jjtuf/jjtuf/internal/osl"
	"github.com/jjtuf/jjtuf/internal/policy"
	"github.com/jjtuf/jjtuf/pkg/gitinterface"
)

// jjtuf refs that need to be synchronized.
var jjtufRefs = []string{
	osl.Ref,          // refs/jjtuf/operation-state-log
	policy.PolicyRef, // refs/jjtuf/policy
	attestations.Ref, // refs/jjtuf/attestations
}

// New creates the sync command.
func New() *cobra.Command {
	var (
		remoteName string
		pushOnly   bool
		fetchOnly  bool
		skipVerify bool
	)

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Synchronize jjtuf metadata with a remote",
		Long: `Fetch and push jjtuf metadata (OSL, policy, attestations) to/from
a remote repository. This ensures all parties have the same security
metadata for independent verification.

After fetching, jjtuf verifies the integrity of the OSL for every
bookmark that has recorded entries, flagging any policy violations.

By default, sync performs both fetch and push. Use --fetch-only or
--push-only to limit the operation.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}

			jjRepo, err := jjinterface.LoadJJRepository(cwd)
			if err != nil {
				return fmt.Errorf("loading jj repository: %w", err)
			}

			gitRepo := jjRepo.GetGitRepository()

			if remoteName == "" {
				remotes, err := gitRepo.GetRemotes()
				if err != nil || len(remotes) == 0 {
					return fmt.Errorf("no remotes configured; specify one with --remote")
				}
				remoteName = remotes[0]
				cmd.Printf("Using remote: %s\n", remoteName)
			}

			// ── Fetch ──────────────────────────────────────────────────────
			if !pushOnly {
				cmd.Printf("Fetching jjtuf metadata from %s...\n", remoteName)
				for _, ref := range jjtufRefs {
					refspec := fmt.Sprintf("+%s:%s", ref, ref)
					if err := gitRepo.FetchRefSpec(remoteName, refspec); err != nil {
						cmd.Printf("  %s: not found on remote (skipped)\n", ref)
					} else {
						cmd.Printf("  %s: fetched\n", ref)
					}
				}

				if !skipVerify {
					if violated := verifyFetchedOSL(cmd, gitRepo); violated {
						return fmt.Errorf("post-fetch OSL verification detected policy violations — review output above")
					}
				}
			}

			// ── Push ───────────────────────────────────────────────────────
			if !fetchOnly {
				cmd.Printf("Pushing jjtuf metadata to %s...\n", remoteName)
				for _, ref := range jjtufRefs {
					if _, err := gitRepo.GetReference(ref); err != nil {
						continue
					}
					if err := gitRepo.PushRef(remoteName, ref); err != nil {
						cmd.Printf("  %s: push failed (%v)\n", ref, err)
					} else {
						cmd.Printf("  %s: pushed\n", ref)
					}
				}
			}

			cmd.Println("Sync complete.")
			return nil
		},
	}

	cmd.Flags().StringVar(&remoteName, "remote", "", "Remote name (defaults to first configured remote)")
	cmd.Flags().BoolVar(&pushOnly, "push-only", false, "Only push local metadata to remote")
	cmd.Flags().BoolVar(&fetchOnly, "fetch-only", false, "Only fetch remote metadata")
	cmd.Flags().BoolVar(&skipVerify, "skip-verify", false, "Skip post-fetch OSL verification (not recommended)")

	return cmd
}

// verifyFetchedOSL verifies the latest OSL entry for every known bookmark.
// Returns true if any policy violations were detected.
func verifyFetchedOSL(cmd *cobra.Command, repo *gitinterface.Repository) bool {
	cmd.Println("Verifying fetched OSL...")

	bookmarks, err := collectOSLBookmarks(repo)
	if err != nil {
		cmd.Printf("  warning: could not enumerate OSL bookmarks: %v\n", err)
		return false
	}

	if len(bookmarks) == 0 {
		cmd.Println("  no OSL entries found")
		return false
	}

	verifier := policy.NewPolicyVerifier(repo)
	anyFailed := false

	for _, bm := range bookmarks {
		result, err := verifier.VerifyRef(bm)
		if err != nil {
			cmd.Printf("  %-30s error: %v\n", bm, err)
			anyFailed = true
			continue
		}
		if result.Passed {
			cmd.Printf("  %-30s OK\n", bm)
		} else {
			cmd.Printf("  %-30s FAILED\n", bm)
			for _, v := range result.Violations {
				cmd.Printf("    - [%s] %s\n", v.RuleName, v.Message)
			}
			anyFailed = true
		}
	}

	if anyFailed {
		cmd.Println("  WARNING: policy violations detected in fetched OSL.")
	} else {
		cmd.Println("  All verified.")
	}
	return anyFailed
}

// collectOSLBookmarks walks the OSL and collects all unique bookmark names
// that appear in operation entries.
func collectOSLBookmarks(repo *gitinterface.Repository) ([]string, error) {
	seen := make(map[string]bool)
	err := osl.IterateEntries(repo, func(entry osl.Entry) bool {
		opEntry, ok := entry.(*osl.OperationEntry)
		if !ok {
			return true
		}
		for _, delta := range opEntry.BookmarkDeltas {
			seen[delta.Name] = true
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	bookmarks := make([]string, 0, len(seen))
	for bm := range seen {
		bookmarks = append(bookmarks, bm)
	}
	return bookmarks, nil
}
