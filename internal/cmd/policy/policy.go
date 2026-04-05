// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jjtuf/jjtuf/internal/jjinterface"
	policyPkg "github.com/jjtuf/jjtuf/internal/policy"
	"github.com/jjtuf/jjtuf/internal/signerverifier/common"
	"github.com/jjtuf/jjtuf/internal/signerverifier/dsse"
	tufv01 "github.com/jjtuf/jjtuf/internal/tuf/v01"
	"github.com/jjtuf/jjtuf/pkg/gitinterface"
)

// New creates the policy management command group.
func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage jjtuf policies",
		Long: `Manage access control policies for the repository. Policies define
which principals (developers, bots) are authorized to modify which
namespaces (bookmarks, file paths) and with what threshold of
signatures required.`,
	}

	cmd.AddCommand(initPolicyCmd())
	cmd.AddCommand(addPrincipalCmd())
	cmd.AddCommand(addRuleCmd())
	cmd.AddCommand(removeRuleCmd())
	cmd.AddCommand(listRulesCmd())
	cmd.AddCommand(applyCmd())

	return cmd
}

func initPolicyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize the primary rule file",
		Long:  `Creates an empty primary rule file in the policy staging area.`,
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

			// Verify jjtuf is initialized
			if _, err := gitRepo.GetReference(policyPkg.PolicyRef); err != nil {
				return fmt.Errorf("jjtuf not initialized. Run 'jjtuf trust init' first")
			}

			// Load current state to get root metadata
			state, err := policyPkg.LoadCurrentState(gitRepo)
			if err != nil {
				return fmt.Errorf("loading policy: %w", err)
			}

			if state.TargetsMetadata != nil {
				return fmt.Errorf("primary rule file already exists")
			}

			// Create empty targets metadata
			targets := tufv01.NewTargetsMetadata()

			// Save to staging
			if err := saveTargetsToStaging(gitRepo, state.RootMetadata, targets); err != nil {
				return fmt.Errorf("saving targets: %w", err)
			}

			cmd.Println("Initialized primary rule file in policy staging.")
			cmd.Println("Use 'jjtuf policy add-principal' and 'jjtuf policy add-rule' to configure,")
			cmd.Println("then 'jjtuf policy apply' to activate.")

			return nil
		},
	}
}

func addPrincipalCmd() *cobra.Command {
	var (
		name    string
		keyPath string
	)

	cmd := &cobra.Command{
		Use:   "add-principal",
		Short: "Add a principal to the policy rule file",
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

			// Load from staging or active
			root, targets, err := loadStagedOrActivePolicy(gitRepo)
			if err != nil {
				return err
			}

			if targets == nil {
				return fmt.Errorf("no rule file found. Run 'jjtuf policy init' first")
			}

			// Load key
			key, err := loadSSHPublicKey(keyPath)
			if err != nil {
				return fmt.Errorf("loading key: %w", err)
			}

			if name == "" {
				name = key.KeyID
			}

			principal := tufv01.NewPrincipalWithKey(name, key)
			if err := targets.AddPrincipal(principal); err != nil {
				return fmt.Errorf("adding principal: %w", err)
			}

			if err := saveTargetsToStaging(gitRepo, root, targets); err != nil {
				return err
			}

			cmd.Printf("Added principal %q to policy staging.\n", name)
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Principal name (defaults to key ID)")
	cmd.Flags().StringVar(&keyPath, "key-path", "", "Path to SSH public key (required)")
	_ = cmd.MarkFlagRequired("key-path")

	return cmd
}

func addRuleCmd() *cobra.Command {
	var (
		name       string
		patterns   []string
		principals []string
		threshold  int
	)

	cmd := &cobra.Command{
		Use:   "add-rule",
		Short: "Add an access control rule to the policy",
		Long: `Add a rule that protects namespace patterns (bookmark:<name> or file:<path>)
and requires signatures from specified principals.`,
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

			root, targets, err := loadStagedOrActivePolicy(gitRepo)
			if err != nil {
				return err
			}

			if targets == nil {
				return fmt.Errorf("no rule file found. Run 'jjtuf policy init' first")
			}

			if err := targets.AddRule(name, principals, patterns, threshold); err != nil {
				return fmt.Errorf("adding rule: %w", err)
			}

			if err := saveTargetsToStaging(gitRepo, root, targets); err != nil {
				return err
			}

			cmd.Printf("Added rule %q protecting %v (threshold: %d, principals: %v)\n",
				name, patterns, threshold, principals)
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Rule name (required)")
	cmd.Flags().StringSliceVar(&patterns, "patterns", nil, "Namespace patterns (e.g., bookmark:main, file:src/*)")
	cmd.Flags().StringSliceVar(&principals, "principals", nil, "Authorized principal names")
	cmd.Flags().IntVar(&threshold, "threshold", 1, "Number of signatures required")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("patterns")
	_ = cmd.MarkFlagRequired("principals")

	return cmd
}

func removeRuleCmd() *cobra.Command {
	var name string

	cmd := &cobra.Command{
		Use:   "remove-rule",
		Short: "Remove a rule from the policy",
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

			root, targets, err := loadStagedOrActivePolicy(gitRepo)
			if err != nil {
				return err
			}

			if targets == nil {
				return fmt.Errorf("no rule file found")
			}

			if err := targets.DeleteRule(name); err != nil {
				return fmt.Errorf("removing rule: %w", err)
			}

			if err := saveTargetsToStaging(gitRepo, root, targets); err != nil {
				return err
			}

			cmd.Printf("Removed rule %q from policy staging.\n", name)
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Rule name to remove (required)")
	_ = cmd.MarkFlagRequired("name")

	return cmd
}

func listRulesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-rules",
		Short: "List all policy rules",
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

			_, targets, err := loadStagedOrActivePolicy(gitRepo)
			if err != nil {
				return err
			}

			if targets == nil {
				cmd.Println("No rule file found. Run 'jjtuf policy init' first.")
				return nil
			}

			// List principals
			principals := targets.GetPrincipals()
			cmd.Printf("Principals (%d):\n", len(principals))
			for id, p := range principals {
				cmd.Printf("  %s (%d keys)\n", id, len(p.Keys()))
			}

			// List rules
			rules := targets.GetRules()
			cmd.Printf("\nRules (%d):\n", len(rules))
			if len(rules) == 0 {
				cmd.Println("  (none)")
			}
			for _, rule := range rules {
				cmd.Printf("  %s:\n", rule.ID())
				cmd.Printf("    Patterns:   %v\n", rule.GetPatterns())
				cmd.Printf("    Principals: %v\n", rule.GetPrincipalIDs())
				cmd.Printf("    Threshold:  %d\n", rule.Threshold())
			}

			return nil
		},
	}
}

func applyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "apply",
		Short: "Apply staged policy to active",
		Long:  `Promotes the staged policy to the active policy ref (refs/jjtuf/policy).`,
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

			// Check staging ref exists
			stagingTipID, err := gitRepo.GetReference(policyPkg.PolicyStagingRef)
			if err != nil {
				return fmt.Errorf("no staged policy found. Use policy commands to stage changes first")
			}

			// Get the tree from staging
			treeID, err := gitRepo.GetCommitTreeID(stagingTipID)
			if err != nil {
				return fmt.Errorf("reading staged policy: %w", err)
			}

			// Commit to active policy ref
			_, err = gitRepo.Commit(treeID, policyPkg.PolicyRef, "Apply policy update", false)
			if err != nil {
				return fmt.Errorf("applying policy: %w", err)
			}

			// Clean up staging ref
			_ = gitRepo.DeleteReference(policyPkg.PolicyStagingRef)

			cmd.Println("Policy applied successfully.")
			return nil
		},
	}
}

// Helper functions

func loadStagedOrActivePolicy(repo *gitinterface.Repository) (*tufv01.RootMetadata, *tufv01.TargetsMetadata, error) {
	// Try staging first
	stagingTipID, err := repo.GetReference(policyPkg.PolicyStagingRef)
	if err == nil {
		state, err := policyPkg.LoadStateForEntry(repo, stagingTipID)
		if err == nil {
			return state.RootMetadata, state.TargetsMetadata, nil
		}
	}

	// Fall back to active
	state, err := policyPkg.LoadCurrentState(repo)
	if err != nil {
		return nil, nil, fmt.Errorf("loading policy: %w", err)
	}

	return state.RootMetadata, state.TargetsMetadata, nil
}

func saveTargetsToStaging(repo *gitinterface.Repository, root *tufv01.RootMetadata, targets *tufv01.TargetsMetadata) error {
	// Serialize root
	rootBytes, err := root.Marshal()
	if err != nil {
		return fmt.Errorf("serializing root: %w", err)
	}
	rootEnv := dsse.NewEnvelope("application/vnd.jjtuf.root+json", rootBytes)
	rootEnvBytes, err := rootEnv.Marshal()
	if err != nil {
		return err
	}
	rootBlobID, err := repo.WriteBlob(rootEnvBytes)
	if err != nil {
		return err
	}

	// Serialize targets
	targetsBytes, err := targets.Marshal()
	if err != nil {
		return fmt.Errorf("serializing targets: %w", err)
	}
	targetsEnv := dsse.NewEnvelope("application/vnd.jjtuf.targets+json", targetsBytes)
	targetsEnvBytes, err := targetsEnv.Marshal()
	if err != nil {
		return err
	}
	targetsBlobID, err := repo.WriteBlob(targetsEnvBytes)
	if err != nil {
		return err
	}

	// Build tree
	tb := gitinterface.NewTreeBuilder(repo)
	treeID, err := tb.WriteRootTreeFromBlobIDs(map[string]gitinterface.Hash{
		"root":    rootBlobID,
		"targets": targetsBlobID,
	})
	if err != nil {
		return err
	}

	_, err = repo.Commit(treeID, policyPkg.PolicyStagingRef, "Update policy", false)
	return err
}

func loadSSHPublicKey(path string) (*common.SSLibKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	keyContent := string(data)
	keyID := fmt.Sprintf("ssh:%x", sha256Short(data))

	return &common.SSLibKey{
		KeyID:   keyID,
		KeyType: common.SSHKeyType,
		KeyVal:  common.KeyVal{Public: keyContent},
		Scheme:  common.SSHSigningScheme,
	}, nil
}

func sha256Short(data []byte) []byte {
	h := make([]byte, 8)
	for i, b := range data {
		h[i%8] ^= b
	}
	return h
}
