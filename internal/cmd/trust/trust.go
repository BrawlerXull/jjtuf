// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jjtuf/jjtuf/internal/jjinterface"
	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
	"github.com/jjtuf/jjtuf/internal/signerverifier/dsse"
	"github.com/jjtuf/jjtuf/internal/signerverifier/loader"
	tufv01 "github.com/jjtuf/jjtuf/internal/tuf/v01"
	"github.com/jjtuf/jjtuf/pkg/gitinterface"
)

const (
	policyRef        = "refs/jjtuf/policy"
	policyStagingRef = "refs/jjtuf/policy-staging"
	rootMetadataPath = "root"
)

// New creates the trust management command group.
func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Manage the root of trust for a jjtuf-enabled repository",
	}

	cmd.AddCommand(initCmd())
	cmd.AddCommand(addRootKeyCmd())
	cmd.AddCommand(addSigstoreKeyCmd())
	cmd.AddCommand(addGlobalRuleCmd())
	cmd.AddCommand(removeGlobalRuleCmd())
	cmd.AddCommand(updateThresholdCmd())
	cmd.AddCommand(inspectCmd())

	return cmd
}

func initCmd() *cobra.Command {
	var (
		keyPath        string
		signingKeyPath string
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize jjtuf metadata in a jj repository",
		Long: `Initialize jjtuf in the current jj repository by creating
the root of trust metadata. This sets up the policy reference
(refs/jjtuf/policy) with the initial root metadata, optionally
signed by the specified key.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("getting working directory: %w", err)
			}

			jjRepo, err := jjinterface.LoadJJRepository(cwd)
			if err != nil {
				return fmt.Errorf("loading jj repository: %w", err)
			}

			gitRepo := jjRepo.GetGitRepository()

			if _, err := gitRepo.GetReference(policyRef); err == nil {
				return fmt.Errorf("jjtuf is already initialized (refs/jjtuf/policy exists)")
			}

			rootMd := tufv01.NewRootMetadata()

			if keyPath != "" {
				key, err := loader.LoadSSLibKeyFromPublicKeyFile(keyPath)
				if err != nil {
					return fmt.Errorf("loading key: %w", err)
				}
				principal := tufv01.NewPrincipal("root", []*common.SSLibKey{key})
				if err := rootMd.AddRootPrincipal(principal); err != nil {
					return fmt.Errorf("adding root principal: %w", err)
				}
				if err := rootMd.AddPrimaryRuleFilePrincipal(principal); err != nil {
					return fmt.Errorf("adding primary rule file principal: %w", err)
				}
			}

			rootBytes, err := rootMd.Marshal()
			if err != nil {
				return fmt.Errorf("serializing root metadata: %w", err)
			}

			env := dsse.NewEnvelope("application/vnd.jjtuf.root+json", rootBytes)
			if signingKeyPath != "" {
				signer, err := loader.LoadSignerVerifierFromFile(signingKeyPath)
				if err != nil {
					return fmt.Errorf("loading signing key: %w", err)
				}
				if err := env.Sign(signer); err != nil {
					return fmt.Errorf("signing root metadata: %w", err)
				}
			}

			envBytes, err := env.Marshal()
			if err != nil {
				return fmt.Errorf("creating DSSE envelope: %w", err)
			}

			rootBlobID, err := gitRepo.WriteBlob(envBytes)
			if err != nil {
				return fmt.Errorf("writing root blob: %w", err)
			}

			tb := gitinterface.NewTreeBuilder(gitRepo)
			treeID, err := tb.WriteRootTreeFromBlobIDs(map[string]gitinterface.Hash{
				rootMetadataPath: rootBlobID,
			})
			if err != nil {
				return fmt.Errorf("creating metadata tree: %w", err)
			}

			_, err = gitRepo.Commit(treeID, policyRef, "Initialize jjtuf root of trust", false)
			if err != nil {
				return fmt.Errorf("creating policy commit: %w", err)
			}

			cmd.Println("Initialized jjtuf root of trust.")
			if keyPath != "" {
				cmd.Printf("Root key added from: %s\n", keyPath)
			} else {
				cmd.Println("No root key specified. Use 'jjtuf trust add-root-key' to add one.")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&keyPath, "key-path", "", "Path to initial root public key (SSH authorized_keys or PEM PUBLIC KEY)")
	cmd.Flags().StringVar(&signingKeyPath, "signing-key", "", "Path to private key to sign the root metadata (optional)")

	return cmd
}

func addRootKeyCmd() *cobra.Command {
	var keyPath string
	var principalName string

	cmd := &cobra.Command{
		Use:   "add-root-key",
		Short: "Add a root key to the jjtuf root of trust",
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

			// Load existing root metadata
			rootMd, err := loadRootMetadata(gitRepo)
			if err != nil {
				return fmt.Errorf("loading root metadata: %w", err)
			}

			// Load the key
			key, err := loader.LoadSSLibKeyFromPublicKeyFile(keyPath)
			if err != nil {
				return fmt.Errorf("loading key: %w", err)
			}

			if principalName == "" {
				principalName = key.KeyID
			}

			principal := tufv01.NewPrincipal(principalName, []*common.SSLibKey{key})
			if err := rootMd.AddRootPrincipal(principal); err != nil {
				return fmt.Errorf("adding root principal: %w", err)
			}

			// Save updated root metadata
			if err := saveRootMetadata(gitRepo, rootMd); err != nil {
				return fmt.Errorf("saving root metadata: %w", err)
			}

			cmd.Printf("Added root key for principal %q\n", principalName)
			return nil
		},
	}

	cmd.Flags().StringVar(&keyPath, "key-path", "", "Path to SSH public key (required)")
	cmd.Flags().StringVar(&principalName, "name", "", "Principal name (defaults to key ID)")
	_ = cmd.MarkFlagRequired("key-path")

	return cmd
}

func addSigstoreKeyCmd() *cobra.Command {
	var (
		identity      string
		issuer        string
		principalName string
		asPolicy      bool
	)

	cmd := &cobra.Command{
		Use:   "add-sigstore-key",
		Short: "Add a Sigstore keyless identity as a trusted principal",
		Long: `Registers a Sigstore (Fulcio/OIDC) identity in the root of trust.
Signatures made by this identity are verified against the Sigstore
public-good infrastructure (Rekor + Fulcio) at verification time.

Example:
  jjtuf trust add-sigstore-key \
    --identity alice@example.com \
    --issuer https://accounts.google.com \
    --name alice`,
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

			rootMd, err := loadRootMetadata(gitRepo)
			if err != nil {
				return fmt.Errorf("loading root metadata: %w", err)
			}

			keyID := fmt.Sprintf("%s::%s", identity, issuer)
			key := &common.SSLibKey{
				KeyID:   keyID,
				KeyType: common.SigstoreKeyType,
				Scheme:  common.FulcioSigningScheme,
				KeyVal: common.KeyVal{
					Identity: identity,
					Issuer:   issuer,
				},
			}

			if principalName == "" {
				principalName = keyID
			}

			principal := tufv01.NewPrincipal(principalName, []*common.SSLibKey{key})
			if err := rootMd.AddRootPrincipal(principal); err != nil {
				return fmt.Errorf("adding root principal: %w", err)
			}
			if asPolicy {
				if err := rootMd.AddPrimaryRuleFilePrincipal(principal); err != nil {
					return fmt.Errorf("adding policy principal: %w", err)
				}
			}

			if err := saveRootMetadata(gitRepo, rootMd); err != nil {
				return fmt.Errorf("saving root metadata: %w", err)
			}

			cmd.Printf("Added Sigstore principal %q (identity: %s, issuer: %s)\n",
				principalName, identity, issuer)
			if asPolicy {
				cmd.Println("Principal also added as a policy signer.")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&identity, "identity", "", "OIDC subject (email or sub claim) of the signer (required)")
	cmd.Flags().StringVar(&issuer, "issuer", "", "OIDC issuer URL (e.g. https://accounts.google.com) (required)")
	cmd.Flags().StringVar(&principalName, "name", "", "Principal name (defaults to identity::issuer)")
	cmd.Flags().BoolVar(&asPolicy, "policy", false, "Also add as a policy-signing principal")
	_ = cmd.MarkFlagRequired("identity")
	_ = cmd.MarkFlagRequired("issuer")

	return cmd
}

func addGlobalRuleCmd() *cobra.Command {
	var (
		name     string
		ruleType string
		patterns []string
	)

	cmd := &cobra.Command{
		Use:   "add-global-rule",
		Short: "Add a global rule to the root of trust",
		Long: `Global rules apply repository-wide. Supported types:
  block-force-pushes: Prevent non-fast-forward updates to matching bookmarks
  threshold: Enforce a minimum signature threshold globally`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}

			jjRepo, err := jjinterface.LoadJJRepository(cwd)
			if err != nil {
				return fmt.Errorf("loading jj repository: %w", err)
			}

			rootMd, err := loadRootMetadata(jjRepo.GetGitRepository())
			if err != nil {
				return err
			}

			rule := &simpleGlobalRule{name: name, ruleType: ruleType, patterns: patterns}
			if err := rootMd.AddGlobalRule(rule); err != nil {
				return fmt.Errorf("adding global rule: %w", err)
			}

			if err := saveRootMetadata(jjRepo.GetGitRepository(), rootMd); err != nil {
				return err
			}

			cmd.Printf("Added global rule %q (type: %s, patterns: %v)\n", name, ruleType, patterns)
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Rule name (required)")
	cmd.Flags().StringVar(&ruleType, "type", "block-force-pushes", "Rule type (block-force-pushes or threshold)")
	cmd.Flags().StringSliceVar(&patterns, "patterns", nil, "Namespace patterns to apply (e.g., bookmark:main)")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("patterns")

	return cmd
}

func removeGlobalRuleCmd() *cobra.Command {
	var name string

	cmd := &cobra.Command{
		Use:   "remove-global-rule",
		Short: "Remove a global rule from the root of trust",
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}

			jjRepo, err := jjinterface.LoadJJRepository(cwd)
			if err != nil {
				return fmt.Errorf("loading jj repository: %w", err)
			}

			rootMd, err := loadRootMetadata(jjRepo.GetGitRepository())
			if err != nil {
				return err
			}

			if err := rootMd.DeleteGlobalRule(name); err != nil {
				return fmt.Errorf("removing global rule: %w", err)
			}

			if err := saveRootMetadata(jjRepo.GetGitRepository(), rootMd); err != nil {
				return err
			}

			cmd.Printf("Removed global rule %q\n", name)
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Rule name to remove (required)")
	_ = cmd.MarkFlagRequired("name")

	return cmd
}

func updateThresholdCmd() *cobra.Command {
	var (
		rootThreshold   int
		policyThreshold int
	)

	cmd := &cobra.Command{
		Use:   "update-threshold",
		Short: "Update root or policy signature thresholds",
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}

			jjRepo, err := jjinterface.LoadJJRepository(cwd)
			if err != nil {
				return fmt.Errorf("loading jj repository: %w", err)
			}

			rootMd, err := loadRootMetadata(jjRepo.GetGitRepository())
			if err != nil {
				return err
			}

			if rootThreshold > 0 {
				if err := rootMd.UpdateRootThreshold(rootThreshold); err != nil {
					return fmt.Errorf("updating root threshold: %w", err)
				}
				cmd.Printf("Root threshold updated to %d\n", rootThreshold)
			}

			if policyThreshold > 0 {
				if err := rootMd.UpdatePrimaryRuleFileThreshold(policyThreshold); err != nil {
					return fmt.Errorf("updating policy threshold: %w", err)
				}
				cmd.Printf("Policy threshold updated to %d\n", policyThreshold)
			}

			if rootThreshold <= 0 && policyThreshold <= 0 {
				return fmt.Errorf("specify --root-threshold or --policy-threshold")
			}

			return saveRootMetadata(jjRepo.GetGitRepository(), rootMd)
		},
	}

	cmd.Flags().IntVar(&rootThreshold, "root-threshold", 0, "New threshold for root metadata changes")
	cmd.Flags().IntVar(&policyThreshold, "policy-threshold", 0, "New threshold for policy rule file changes")

	return cmd
}

// simpleGlobalRule implements tuf.GlobalRule for CLI use.
type simpleGlobalRule struct {
	name     string
	ruleType string
	patterns []string
}

func (r *simpleGlobalRule) Type() string       { return r.ruleType }
func (r *simpleGlobalRule) Name() string       { return r.name }
func (r *simpleGlobalRule) Patterns() []string { return r.patterns }

func inspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect",
		Short: "Display the current root of trust state",
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}

			jjRepo, err := jjinterface.LoadJJRepository(cwd)
			if err != nil {
				return fmt.Errorf("loading jj repository: %w", err)
			}

			rootMd, err := loadRootMetadata(jjRepo.GetGitRepository())
			if err != nil {
				return fmt.Errorf("loading root metadata: %w", err)
			}

			// Display root of trust info
			cmd.Println("jjtuf Root of Trust")
			cmd.Println("===================")
			cmd.Printf("Schema Version: %s\n", rootMd.SchemaVersion())

			if loc := rootMd.GetRepositoryLocation(); loc != "" {
				cmd.Printf("Repository Location: %s\n", loc)
			}

			rootThreshold, _ := rootMd.GetRootThreshold()
			cmd.Printf("\nRoot Threshold: %d\n", rootThreshold)

			rootPrincipals, _ := rootMd.GetRootPrincipals()
			cmd.Printf("Root Principals (%d):\n", len(rootPrincipals))
			for _, p := range rootPrincipals {
				cmd.Printf("  - %s (%d keys)\n", p.ID(), len(p.Keys()))
			}

			policyThreshold, _ := rootMd.GetPrimaryRuleFileThreshold()
			cmd.Printf("\nPolicy Threshold: %d\n", policyThreshold)

			policyPrincipals, _ := rootMd.GetPrimaryRuleFilePrincipals()
			cmd.Printf("Policy Principals (%d):\n", len(policyPrincipals))
			for _, p := range policyPrincipals {
				cmd.Printf("  - %s (%d keys)\n", p.ID(), len(p.Keys()))
			}

			globalRules := rootMd.GetGlobalRules()
			if len(globalRules) > 0 {
				cmd.Println("\nGlobal Rules:")
				for ruleType, rules := range globalRules {
					for _, rule := range rules {
						cmd.Printf("  - [%s] %s: %v\n", ruleType, rule.Name(), rule.Patterns())
					}
				}
			}

			return nil
		},
	}
}

// Helper functions

func loadRootMetadata(repo *gitinterface.Repository) (*tufv01.RootMetadata, error) {
	policyTipID, err := repo.GetReference(policyRef)
	if err != nil {
		return nil, fmt.Errorf("jjtuf not initialized: %w", err)
	}

	// Get the tree from the policy commit
	treeID, err := repo.GetCommitTreeID(policyTipID)
	if err != nil {
		return nil, fmt.Errorf("reading policy tree: %w", err)
	}

	rootBlobID, err := repo.GetPathIDInTree(rootMetadataPath, treeID)
	if err != nil {
		return nil, fmt.Errorf("root metadata not found in policy: %w", err)
	}

	envBytes, err := repo.ReadBlob(rootBlobID)
	if err != nil {
		return nil, fmt.Errorf("reading root metadata blob: %w", err)
	}

	env, err := dsse.Unmarshal(envBytes)
	if err != nil {
		// Try as raw JSON (for backward compat)
		return tufv01.UnmarshalRootMetadata(envBytes)
	}

	payload, err := env.DecodePayload()
	if err != nil {
		return nil, fmt.Errorf("decoding DSSE payload: %w", err)
	}

	return tufv01.UnmarshalRootMetadata(payload)
}

func saveRootMetadata(repo *gitinterface.Repository, rootMd *tufv01.RootMetadata) error {
	rootBytes, err := rootMd.Marshal()
	if err != nil {
		return err
	}

	env := dsse.NewEnvelope("application/vnd.jjtuf.root+json", rootBytes)
	envBytes, err := env.Marshal()
	if err != nil {
		return err
	}

	rootBlobID, err := repo.WriteBlob(envBytes)
	if err != nil {
		return err
	}

	// Preserve existing entries in the policy tree (e.g., targets metadata)
	entries := map[string]gitinterface.Hash{
		rootMetadataPath: rootBlobID,
	}

	policyTipID, err := repo.GetReference(policyRef)
	if err == nil {
		treeID, err := repo.GetCommitTreeID(policyTipID)
		if err == nil {
			// Check if targets blob exists and preserve it
			targetsBlobID, err := repo.GetPathIDInTree("targets", treeID)
			if err == nil {
				entries["targets"] = targetsBlobID
			}
		}
	}

	tb := gitinterface.NewTreeBuilder(repo)
	treeID, err := tb.WriteRootTreeFromBlobIDs(entries)
	if err != nil {
		return err
	}

	_, err = repo.Commit(treeID, policyRef, "Update root of trust metadata", false)
	return err
}

// ensure json is used (for potential future use)
var _ = json.Marshal
