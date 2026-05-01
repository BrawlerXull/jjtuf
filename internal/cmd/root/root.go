// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package root

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/jjtuf/jjtuf/internal/cmd/attest"
	"github.com/jjtuf/jjtuf/internal/cmd/cache"
	"github.com/jjtuf/jjtuf/internal/cmd/hook"
	"github.com/jjtuf/jjtuf/internal/cmd/osl"
	"github.com/jjtuf/jjtuf/internal/cmd/policy"
	"github.com/jjtuf/jjtuf/internal/cmd/sync"
	"github.com/jjtuf/jjtuf/internal/cmd/trust"
	"github.com/jjtuf/jjtuf/internal/cmd/verify"
	"github.com/jjtuf/jjtuf/internal/signerverifier/dsse"
	"github.com/jjtuf/jjtuf/internal/signerverifier/loader"
)

func init() {
	// Wire the production verifier loader so DSSE signature verification works.
	dsse.SetDefaultLoader(loader.LoadVerifierFromSSLibKey)
}

// New creates the root cobra command for jjtuf.
func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jjtuf",
		Short: "jjtuf - TUF-based security for Jujutsu repositories",
		Long: `jjtuf provides forge-agnostic security for Jujutsu (jj) repositories
using The Update Framework (TUF). It enables decentralized policy
declaration, activity tracking, and policy enforcement.

jjtuf is inspired by gittuf and adapts its security model for jj's
operation-based architecture.`,
		SilenceUsage: true,
	}

	// Cobra defaults cmd.Print* to stderr; route normal output to stdout
	// so users (and pipelines) see results on the expected stream.
	cmd.SetOut(os.Stdout)
	cmd.SetErr(os.Stderr)

	cmd.AddCommand(trust.New())
	cmd.AddCommand(policy.New())
	cmd.AddCommand(osl.New())
	cmd.AddCommand(attest.New())
	cmd.AddCommand(verify.New())
	cmd.AddCommand(sync.New())
	cmd.AddCommand(cache.New())
	cmd.AddCommand(hook.New())
	cmd.AddCommand(versionCmd())

	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print jjtuf version",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println("jjtuf v0.1.0-dev")
		},
	}
}
