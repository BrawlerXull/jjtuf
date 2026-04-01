// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"github.com/spf13/cobra"
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
	cmd.AddCommand(listRulesCmd())

	return cmd
}

func initPolicyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize the primary rule file",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("Policy initialization will be implemented in Phase 2.")
			return nil
		},
	}
}

func listRulesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-rules",
		Short: "List all policy rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("Policy listing will be implemented in Phase 2.")
			return nil
		},
	}
}
