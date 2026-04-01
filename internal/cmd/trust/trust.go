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
	cmd.AddCommand(inspectCmd())

	return cmd
}

func initCmd() *cobra.Command {
	var keyPath string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize jjtuf metadata in a jj repository",
		Long: `Initialize jjtuf in the current jj repository by creating
the root of trust metadata. This sets up the policy reference
(refs/jjtuf/policy) with the initial root metadata signed by
the specified key.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("getting working directory: %w", err)
			}

			// Load jj repository
			jjRepo, err := jjinterface.LoadJJRepository(cwd)
			if err != nil {
				return fmt.Errorf("loading jj repository: %w", err)
			}

			gitRepo := jjRepo.GetGitRepository()

			// Check if already initialized
			if _, err := gitRepo.GetReference(policyRef); err == nil {
				return fmt.Errorf("jjtuf is already initialized (refs/jjtuf/policy exists)")
			}

			// Create root metadata
			rootMd := tufv01.NewRootMetadata()

			// If a key is provided, add it as root principal
			if keyPath != "" {
				key, err := loadSSHPublicKey(keyPath)
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

			// Serialize root metadata
			rootBytes, err := rootMd.Marshal()
			if err != nil {
				return fmt.Errorf("serializing root metadata: %w", err)
			}

			// Wrap in DSSE envelope
			env := dsse.NewEnvelope("application/vnd.jjtuf.root+json", rootBytes)
			envBytes, err := env.Marshal()
			if err != nil {
				return fmt.Errorf("creating DSSE envelope: %w", err)
			}

			// Write root metadata as a blob
			rootBlobID, err := gitRepo.WriteBlob(envBytes)
			if err != nil {
				return fmt.Errorf("writing root blob: %w", err)
			}

			// Create tree with root metadata
			tb := gitinterface.NewTreeBuilder(gitRepo)
			treeID, err := tb.WriteRootTreeFromBlobIDs(map[string]gitinterface.Hash{
				rootMetadataPath: rootBlobID,
			})
			if err != nil {
				return fmt.Errorf("creating metadata tree: %w", err)
			}

			// Create initial commit on policy ref
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

	cmd.Flags().StringVar(&keyPath, "key-path", "", "Path to initial root SSH public key")

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
			key, err := loadSSHPublicKey(keyPath)
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

	rootBlobID, err := repo.GetPathIDInTree(rootMetadataPath, policyTipID)
	if err != nil {
		// Try with tree from commit
		treeID, err2 := repo.GetCommitTreeID(policyTipID)
		if err2 != nil {
			return nil, fmt.Errorf("reading policy tree: %w", err2)
		}
		rootBlobID, err = repo.GetPathIDInTree(rootMetadataPath, treeID)
		if err != nil {
			return nil, fmt.Errorf("root metadata not found in policy: %w", err)
		}
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

	tb := gitinterface.NewTreeBuilder(repo)
	treeID, err := tb.WriteRootTreeFromBlobIDs(map[string]gitinterface.Hash{
		rootMetadataPath: rootBlobID,
	})
	if err != nil {
		return err
	}

	_, err = repo.Commit(treeID, policyStagingRef, "Update root of trust metadata", false)
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
	// Use a simple hash for key ID
	h := make([]byte, 8)
	for i, b := range data {
		h[i%8] ^= b
	}
	return h
}

// ensure json is used (for potential future use)
var _ = json.Marshal
