// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"github.com/spf13/cobra"
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

	return cmd
}

func refCmd() *cobra.Command {
	var full bool

	cmd := &cobra.Command{
		Use:   "ref <bookmark>",
		Short: "Verify a bookmark against policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if full {
				cmd.Printf("Full history verification for %q will be implemented in Phase 2.\n", args[0])
			} else {
				cmd.Printf("Latest entry verification for %q will be implemented in Phase 2.\n", args[0])
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&full, "full", false, "Verify full history from first entry")

	return cmd
}
