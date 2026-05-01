// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jjtuf/jjtuf/internal/attestations"
	"github.com/jjtuf/jjtuf/internal/jjinterface"
	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
	"github.com/jjtuf/jjtuf/internal/signerverifier/dsse"
	"github.com/jjtuf/jjtuf/internal/signerverifier/loader"
	sigstoresigner "github.com/jjtuf/jjtuf/internal/signerverifier/sigstore"
)

// resolveSigner returns a SignerVerifier from either a key file (file-based
// signing) or Sigstore keyless signing using ambient OIDC credentials.
// Exactly one of keyFile or useSigstore must be set.
func resolveSigner(keyFile string, useSigstore bool) (common.SignerVerifier, error) {
	if useSigstore && keyFile != "" {
		return nil, fmt.Errorf("cannot use --sigstore and --key-file together")
	}
	if !useSigstore && keyFile == "" {
		return nil, fmt.Errorf("specify either --key-file or --sigstore")
	}
	if useSigstore {
		return sigstoresigner.NewFromEnvironment()
	}
	return loader.LoadSignerVerifierFromFile(keyFile)
}

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
		keyFile     string
		useSigstore bool
	)

	cmd := &cobra.Command{
		Use:   "authorize",
		Short: "Create a reference authorization attestation",
		Long: `Pre-authorize a bookmark update by creating a signed reference
authorization. This is used when a policy rule requires multiple
signatures (threshold > 1) — one developer creates the authorization
attestation, and another performs the actual update.

Provide exactly one of --key-file or --sigstore:
  --key-file points to a PKCS#8 / SEC1 / PKCS#1 / OpenSSH private key.
  --sigstore performs keyless signing using ambient OIDC credentials
    (SIGSTORE_ID_TOKEN env var or GitHub Actions OIDC).`,
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

			signer, err := resolveSigner(keyFile, useSigstore)
			if err != nil {
				return err
			}

			currentAttestations, err := attestations.LoadCurrentAttestations(gitRepo)
			if err != nil {
				return fmt.Errorf("loading attestations: %w", err)
			}

			// Try to load an existing authorization for this (bookmark, from, to) triple
			// so that multiple signers can append their signatures to the same envelope.
			// fromID is normalized inside the path functions so all "no parent"
			// sentinels resolve to the same envelope.
			var env *dsse.Envelope
			existing, loadErr := currentAttestations.GetReferenceAuthorizationFor(gitRepo, bookmark, fromID, targetTree)
			if loadErr == nil {
				env = existing
			} else {
				env, err = attestations.NewReferenceAuthorization(bookmark, fromID, targetTree)
				if err != nil {
					return fmt.Errorf("creating authorization: %w", err)
				}
			}

			if err := env.Sign(signer); err != nil {
				return fmt.Errorf("signing authorization: %w", err)
			}

			if err := currentAttestations.SetReferenceAuthorization(
				gitRepo, env, bookmark, fromID, targetTree); err != nil {
				return fmt.Errorf("storing authorization: %w", err)
			}

			if err := currentAttestations.Commit(gitRepo); err != nil {
				return fmt.Errorf("committing attestations: %w", err)
			}

			cmd.Printf("Created reference authorization for bookmark %q\n", bookmark)
			cmd.Printf("  From:        %s\n", truncate(fromID, 12))
			cmd.Printf("  Target Tree: %s\n", truncate(targetTree, 12))
			cmd.Printf("  Signed by:   %s\n", signer.KeyID())

			return nil
		},
	}

	cmd.Flags().StringVar(&bookmark, "bookmark", "", "Bookmark name (required)")
	cmd.Flags().StringVar(&fromID, "from", "", "Current commit ID of the bookmark (empty or all-zeros for a new bookmark)")
	cmd.Flags().StringVar(&targetTree, "to", "", "Target tree ID after update (required)")
	cmd.Flags().StringVar(&keyFile, "key-file", "", "Path to private key for signing")
	cmd.Flags().BoolVar(&useSigstore, "sigstore", false, "Use Sigstore keyless signing with ambient OIDC credentials")
	_ = cmd.MarkFlagRequired("bookmark")
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
		keyFile     string
		useSigstore bool
	)

	cmd := &cobra.Command{
		Use:   "approve",
		Short: "Create a code review approval attestation",
		Long: `Record a code review approval from a forge (GitHub, Gerrit, etc.)
as an attestation. This can be used to satisfy policy rules that
require code review approvals.

Provide exactly one of --key-file or --sigstore:
  --key-file points to a PKCS#8 / SEC1 / PKCS#1 / OpenSSH private key.
  --sigstore performs keyless signing using ambient OIDC credentials.`,
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

			signer, err := resolveSigner(keyFile, useSigstore)
			if err != nil {
				return err
			}

			env, err := attestations.NewCodeReviewApproval(
				bookmark, fromID, targetTree, system, reviewID, true)
			if err != nil {
				return fmt.Errorf("creating approval: %w", err)
			}

			if err := env.Sign(signer); err != nil {
				return fmt.Errorf("signing approval: %w", err)
			}

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
			cmd.Printf("  System:    %s\n", system)
			if reviewID != "" {
				cmd.Printf("  Review ID: %s\n", reviewID)
			}
			cmd.Printf("  Signed by: %s\n", signer.KeyID())

			return nil
		},
	}

	cmd.Flags().StringVar(&bookmark, "bookmark", "", "Bookmark name (required)")
	cmd.Flags().StringVar(&fromID, "from", "", "Current commit ID (empty or all-zeros for a new bookmark)")
	cmd.Flags().StringVar(&targetTree, "to", "", "Target tree ID (required)")
	cmd.Flags().StringVar(&system, "system", "", "Code review system (e.g., github, gerrit) (required)")
	cmd.Flags().StringVar(&reviewID, "review-id", "", "System-specific review ID (e.g., PR number)")
	cmd.Flags().StringVar(&keyFile, "key-file", "", "Path to private key for signing")
	cmd.Flags().BoolVar(&useSigstore, "sigstore", false, "Use Sigstore keyless signing with ambient OIDC credentials")
	_ = cmd.MarkFlagRequired("bookmark")
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
