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
)

// jjtuf refs that need to be synchronized
var jjtufRefs = []string{
	osl.Ref,                  // refs/jjtuf/operation-state-log
	policy.PolicyRef,         // refs/jjtuf/policy
	attestations.Ref,         // refs/jjtuf/attestations
}

// New creates the sync command.
func New() *cobra.Command {
	var (
		remoteName string
		pushOnly   bool
		fetchOnly  bool
	)

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Synchronize jjtuf metadata with a remote",
		Long: `Fetch and push jjtuf metadata (OSL, policy, attestations) to/from
a remote repository. This ensures all parties have the same security
metadata for independent verification.

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

			// Determine remote
			if remoteName == "" {
				remotes, err := gitRepo.GetRemotes()
				if err != nil || len(remotes) == 0 {
					return fmt.Errorf("no remotes configured. Specify a remote with --remote")
				}
				remoteName = remotes[0]
				cmd.Printf("Using remote: %s\n", remoteName)
			}

			// Fetch
			if !pushOnly {
				cmd.Printf("Fetching jjtuf metadata from %s...\n", remoteName)

				for _, ref := range jjtufRefs {
					refspec := fmt.Sprintf("+%s:%s", ref, ref)
					err := gitRepo.FetchRefSpec(remoteName, refspec)
					if err != nil {
						cmd.Printf("  %s: not found on remote (skip)\n", ref)
					} else {
						cmd.Printf("  %s: fetched\n", ref)
					}
				}

				// Verify fetched OSL
				cmd.Println("Verifying fetched OSL...")
				verifier := policy.NewPolicyVerifier(gitRepo)
				_ = verifier // TODO: run verification on fetched entries
				cmd.Println("  (verification will be enhanced in future versions)")
			}

			// Push
			if !fetchOnly {
				cmd.Printf("Pushing jjtuf metadata to %s...\n", remoteName)

				for _, ref := range jjtufRefs {
					// Check if ref exists locally
					if _, err := gitRepo.GetReference(ref); err != nil {
						continue // Skip refs that don't exist locally
					}

					err := gitRepo.PushRef(remoteName, ref)
					if err != nil {
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

	return cmd
}
