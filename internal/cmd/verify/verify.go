// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jjtuf/jjtuf/internal/jjinterface"
	"github.com/jjtuf/jjtuf/internal/policy"
)

// New creates the verification command group.
func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify repository state against policy",
		Long: `Verify that bookmark updates in the Operation State Log comply
with the declared jjtuf policies. Verification can check the
latest entry, full history, or assess merge readiness.`,
	}

	cmd.AddCommand(refCmd())
	cmd.AddCommand(mergeableCmd())

	return cmd
}

func refCmd() *cobra.Command {
	var full bool

	cmd := &cobra.Command{
		Use:   "ref <bookmark>",
		Short: "Verify a bookmark against policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

			cwd, err := os.Getwd()
			if err != nil {
				return err
			}

			jjRepo, err := jjinterface.LoadJJRepository(cwd)
			if err != nil {
				return fmt.Errorf("loading jj repository: %w", err)
			}

			gitRepo := jjRepo.GetGitRepository()
			verifier := policy.NewPolicyVerifier(gitRepo)

			if full {
				// Full history verification
				results, err := verifier.VerifyRefFull(target)
				if err != nil {
					return fmt.Errorf("verification failed: %w", err)
				}

				passed := 0
				failed := 0
				for _, result := range results {
					if result.Passed {
						passed++
					} else {
						failed++
						cmd.Printf("FAIL Entry %s:\n", result.EntryID.String()[:12])
						for _, v := range result.Violations {
							cmd.Printf("  - [%s] %s\n", v.BookmarkName, v.Message)
						}
					}
				}

				cmd.Printf("\nVerification complete: %d passed, %d failed (out of %d entries)\n",
					passed, failed, len(results))

				if failed > 0 {
					return fmt.Errorf("%w: %d violations found", policy.ErrVerificationFailed, failed)
				}
			} else {
				// Latest entry only
				result, err := verifier.VerifyRef(target)
				if err != nil {
					return fmt.Errorf("verification failed: %w", err)
				}

				if result.Passed {
					cmd.Printf("OK Bookmark %q: verification passed (entry %s)\n",
						target, result.EntryID.String()[:12])
				} else {
					cmd.Printf("FAIL Bookmark %q: verification failed (entry %s)\n",
						target, result.EntryID.String()[:12])
					for _, v := range result.Violations {
						cmd.Printf("  - [%s] %s\n", v.BookmarkName, v.Message)
					}
					return policy.ErrVerificationFailed
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&full, "full", false, "Verify full history from first entry")

	return cmd
}

func mergeableCmd() *cobra.Command {
	var target string
	var feature string

	cmd := &cobra.Command{
		Use:   "mergeable",
		Short: "Check if a feature bookmark can be merged into a target",
		Long: `Verify that sufficient authorizations and approvals exist for
merging the feature bookmark into the target bookmark. Returns
whether the merge is allowed and if an authorized signature is
needed on the OSL entry.`,
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
			verifier := policy.NewPolicyVerifier(gitRepo)

			needsSignature, err := verifier.VerifyMergeable(target, feature)
			if err != nil {
				cmd.Printf("FAIL Cannot merge %q into %q\n", feature, target)
				return err
			}

			if needsSignature {
				cmd.Printf("OK Merge %q -> %q is allowed (authorized OSL entry signature required)\n",
					feature, target)
			} else {
				cmd.Printf("OK Merge %q -> %q is allowed (anyone can perform the merge)\n",
					feature, target)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&target, "target", "", "Target bookmark to merge into (required)")
	cmd.Flags().StringVar(&feature, "feature", "", "Feature bookmark to merge (required)")
	_ = cmd.MarkFlagRequired("target")
	_ = cmd.MarkFlagRequired("feature")

	return cmd
}
