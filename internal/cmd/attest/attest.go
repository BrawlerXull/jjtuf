// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jjtuf/jjtuf/internal/attestations"
	"github.com/jjtuf/jjtuf/internal/jjinterface"
)

// New creates the attestation command group.
func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Manage attestations",
		Long: `Create and manage attestations for repository actions. Attestations
are signed metadata that pre-authorize changes, enabling multi-party
approval workflows where threshold signatures are required.`,
	}

	cmd.AddCommand(authorizeCmd())
	cmd.AddCommand(approveCmd())
	cmd.AddCommand(listCmd())

	return cmd
}

func authorizeCmd() *cobra.Command {
	var (
		bookmark    string
		fromID      string
		targetTree  string
		signerKeyID string
	)

	cmd := &cobra.Command{
		Use:   "authorize",
		Short: "Create a reference authorization attestation",
		Long: `Pre-authorize a bookmark update by creating a signed reference
authorization. This is used when a policy rule requires multiple
signatures (threshold > 1) — one developer creates the authorization
attestation, and another performs the actual update.`,
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

			// Create the authorization attestation
			env, err := attestations.NewReferenceAuthorization(bookmark, fromID, targetTree)
			if err != nil {
				return fmt.Errorf("creating authorization: %w", err)
			}

			// Add the signer's key ID to the envelope
			if signerKeyID != "" {
				// In a real implementation, this would sign with the actual key
				// For now, we record the key ID as the signer
				env.AddSignature(signerKeyID, []byte("placeholder-signature"))
			}

			// Load current attestations and add the new one
			currentAttestations, err := attestations.LoadCurrentAttestations(gitRepo)
			if err != nil {
				return fmt.Errorf("loading attestations: %w", err)
			}

			if err := currentAttestations.SetReferenceAuthorization(
				gitRepo, env, bookmark, fromID, targetTree); err != nil {
				return fmt.Errorf("storing authorization: %w", err)
			}

			// Commit the attestations
			if err := currentAttestations.Commit(gitRepo); err != nil {
				return fmt.Errorf("committing attestations: %w", err)
			}

			cmd.Printf("Created reference authorization for bookmark %q\n", bookmark)
			cmd.Printf("  From: %s\n", truncate(fromID, 12))
			cmd.Printf("  Target Tree: %s\n", truncate(targetTree, 12))
			if signerKeyID != "" {
				cmd.Printf("  Signer: %s\n", signerKeyID)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&bookmark, "bookmark", "", "Bookmark name (required)")
	cmd.Flags().StringVar(&fromID, "from", "", "Current commit ID of the bookmark (required)")
	cmd.Flags().StringVar(&targetTree, "to", "", "Target tree ID after update (required)")
	cmd.Flags().StringVar(&signerKeyID, "signer-key-id", "", "Key ID of the authorizing principal")
	_ = cmd.MarkFlagRequired("bookmark")
	_ = cmd.MarkFlagRequired("from")
	_ = cmd.MarkFlagRequired("to")

	return cmd
}

func approveCmd() *cobra.Command {
	var (
		bookmark    string
		fromID      string
		targetTree  string
		system      string
		reviewID    string
		signerKeyID string
	)

	cmd := &cobra.Command{
		Use:   "approve",
		Short: "Create a code review approval attestation",
		Long: `Record a code review approval from a forge (GitHub, Gerrit, etc.)
as an attestation. This can be used to satisfy policy rules that
require code review approvals.`,
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

			// Create the approval attestation
			env, err := attestations.NewCodeReviewApproval(
				bookmark, fromID, targetTree, system, reviewID, true)
			if err != nil {
				return fmt.Errorf("creating approval: %w", err)
			}

			if signerKeyID != "" {
				env.AddSignature(signerKeyID, []byte("placeholder-signature"))
			}

			// Load and update attestations
			currentAttestations, err := attestations.LoadCurrentAttestations(gitRepo)
			if err != nil {
				return fmt.Errorf("loading attestations: %w", err)
			}

			if err := currentAttestations.SetCodeReviewApproval(
				gitRepo, env, bookmark, fromID, targetTree, system); err != nil {
				return fmt.Errorf("storing approval: %w", err)
			}

			if err := currentAttestations.Commit(gitRepo); err != nil {
				return fmt.Errorf("committing attestations: %w", err)
			}

			cmd.Printf("Created code review approval for bookmark %q\n", bookmark)
			cmd.Printf("  System: %s\n", system)
			if reviewID != "" {
				cmd.Printf("  Review ID: %s\n", reviewID)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&bookmark, "bookmark", "", "Bookmark name (required)")
	cmd.Flags().StringVar(&fromID, "from", "", "Current commit ID (required)")
	cmd.Flags().StringVar(&targetTree, "to", "", "Target tree ID (required)")
	cmd.Flags().StringVar(&system, "system", "", "Code review system (e.g., github, gerrit) (required)")
	cmd.Flags().StringVar(&reviewID, "review-id", "", "System-specific review ID (e.g., PR number)")
	cmd.Flags().StringVar(&signerKeyID, "signer-key-id", "", "Key ID of the approving principal")
	_ = cmd.MarkFlagRequired("bookmark")
	_ = cmd.MarkFlagRequired("from")
	_ = cmd.MarkFlagRequired("to")
	_ = cmd.MarkFlagRequired("system")

	return cmd
}

func listCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all attestations",
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
			currentAttestations, err := attestations.LoadCurrentAttestations(gitRepo)
			if err != nil {
				return fmt.Errorf("loading attestations: %w", err)
			}

			auths := currentAttestations.ListReferenceAuthorizations()
			cmd.Printf("Reference Authorizations (%d):\n", len(auths))
			for _, a := range auths {
				cmd.Printf("  %s\n", a)
			}

			approvals := currentAttestations.ListCodeReviewApprovals()
			cmd.Printf("\nCode Review Approvals (%d):\n", len(approvals))
			for _, a := range approvals {
				cmd.Printf("  %s\n", a)
			}

			return nil
		},
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
