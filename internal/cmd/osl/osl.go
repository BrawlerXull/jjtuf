// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package osl

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jjtuf/jjtuf/internal/jjinterface"
	oslpkg "github.com/jjtuf/jjtuf/internal/osl"
	"github.com/jjtuf/jjtuf/pkg/gitinterface"
)

// New creates the OSL command group.
func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "osl",
		Short: "Manage the Operation State Log",
	}

	cmd.AddCommand(recordCmd())
	cmd.AddCommand(logCmd())
	cmd.AddCommand(annotateCmd())

	return cmd
}

func recordCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "record",
		Short: "Record current jj operation state to the OSL",
		Long: `Records the current jj operation(s) as new entries in the
Operation State Log. This computes bookmark deltas between the
previous recorded state and the current state, creating signed
OSL entries for each non-snapshot operation.`,
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

			// Get current operation heads
			opHeadIDs, err := jjRepo.GetOpHeadIDs()
			if err != nil {
				return fmt.Errorf("reading operation heads: %w", err)
			}

			recorded := 0
			for _, opID := range opHeadIDs {
				// Read the operation
				op, err := jjRepo.ReadOperation(opID)
				if err != nil {
					cmd.PrintErrf("Warning: could not read operation %s: %v\n", opID[:12], err)
					continue
				}

				// Skip snapshot operations
				if !jjinterface.ShouldRecordOperation(op) {
					cmd.Printf("Skipping snapshot operation %s\n", opID[:12])
					continue
				}

				// Compute view digest
				viewDigest, err := jjRepo.ComputeViewDigest(op.ViewID)
				if err != nil {
					cmd.PrintErrf("Warning: could not compute view digest for %s: %v\n", opID[:12], err)
					continue
				}

				// Read current and parent views to compute deltas
				var deltas []oslpkg.BookmarkDelta
				currentView, err := jjRepo.ReadView(op.ViewID)
				if err == nil {
					// Try to read parent view for delta computation
					if len(op.ParentIDs) > 0 {
						parentOp, err := jjRepo.ReadOperation(op.ParentIDs[0])
						if err == nil {
							parentView, err := jjRepo.ReadView(parentOp.ViewID)
							if err == nil {
								deltas = jjinterface.ComputeBookmarkDeltas(parentView, currentView)
							}
						}
					}

					if deltas == nil {
						// No parent view available — record all bookmarks as new
						deltas = jjinterface.ComputeBookmarkDeltas(nil, currentView)
					}
				}

				// Create OSL entry
				entry := oslpkg.NewOperationEntry(opID, op.ParentIDs, viewDigest, deltas)
				if err := entry.Commit(gitRepo, false); err != nil {
					return fmt.Errorf("committing OSL entry for %s: %w", opID[:12], err)
				}

				recorded++
				cmd.Printf("Recorded OSL entry #%d for operation %s", entry.Number, opID[:12])
				if len(deltas) > 0 {
					cmd.Printf(" (%d bookmark changes)", len(deltas))
				}
				cmd.Println()
			}

			if recorded == 0 {
				cmd.Println("No operations to record.")
			} else {
				cmd.Printf("Recorded %d OSL entries.\n", recorded)
			}

			return nil
		},
	}

	return cmd
}

func logCmd() *cobra.Command {
	var bookmark string
	var limit int

	cmd := &cobra.Command{
		Use:   "log",
		Short: "Display the Operation State Log",
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

			count := 0
			err = oslpkg.IterateEntries(gitRepo, func(entry oslpkg.Entry) bool {
				if limit > 0 && count >= limit {
					return false
				}

				switch e := entry.(type) {
				case *oslpkg.OperationEntry:
					// Filter by bookmark if specified
					if bookmark != "" {
						found := false
						for _, delta := range e.BookmarkDeltas {
							if delta.Name == bookmark {
								found = true
								break
							}
						}
						if !found {
							return true // Skip, keep iterating
						}
					}

					cmd.Printf("Entry #%d [Operation] %s\n", e.Number, e.ID.String()[:12])
					cmd.Printf("  Operation: %s\n", truncate(e.OperationID, 16))
					cmd.Printf("  View Digest: %s\n", truncate(e.ViewDigest, 16))
					if len(e.BookmarkDeltas) > 0 {
						cmd.Println("  Bookmark Changes:")
						for _, delta := range e.BookmarkDeltas {
							fromStr := truncate(delta.FromID, 12)
							if fromStr == "" {
								fromStr = "(new)"
							}
							toStr := truncate(delta.ToID, 12)
							if toStr == "" {
								toStr = "(deleted)"
							}
							conflictStr := ""
							if delta.Conflict {
								conflictStr = " [CONFLICT]"
							}
							cmd.Printf("    %s: %s -> %s%s\n", delta.Name, fromStr, toStr, conflictStr)
						}
					}
					cmd.Println()

				case *oslpkg.AnnotationEntry:
					cmd.Printf("Entry #%d [Annotation] %s\n", e.Number, e.ID.String()[:12])
					cmd.Printf("  Skip: %t\n", e.Skip)
					if e.Message != "" {
						cmd.Printf("  Message: %s\n", e.Message)
					}
					cmd.Printf("  Applies to: ")
					for i, id := range e.OSLEntryIDs {
						if i > 0 {
							cmd.Print(", ")
						}
						cmd.Print(id.String()[:12])
					}
					cmd.Println("")

				case *oslpkg.PropagationEntry:
					cmd.Printf("Entry #%d [Propagation] %s\n", e.Number, e.ID.String()[:12])
					cmd.Printf("  Upstream: %s\n", e.UpstreamRepository)
					cmd.Printf("  Upstream Entry: %s\n", e.UpstreamEntryID.String()[:12])
					cmd.Println()
				}

				count++
				return true
			})

			if err != nil {
				if err == oslpkg.ErrOSLEntryNotFound {
					cmd.Println("No OSL entries found. Use 'jjtuf osl record' to create entries.")
					return nil
				}
				return err
			}

			if count == 0 {
				if bookmark != "" {
					cmd.Printf("No OSL entries found for bookmark %q.\n", bookmark)
				} else {
					cmd.Println("No OSL entries found.")
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&bookmark, "bookmark", "", "Filter entries by bookmark name")
	cmd.Flags().IntVarP(&limit, "limit", "n", 0, "Maximum number of entries to display")

	return cmd
}

func annotateCmd() *cobra.Command {
	var entryIDs []string
	var skip bool
	var message string

	cmd := &cobra.Command{
		Use:   "annotate",
		Short: "Create an annotation entry in the OSL",
		Long: `Create an annotation entry that references one or more prior OSL
entries. Annotations can mark entries as skipped (revoked) or add
context messages without breaking the append-only chain.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(entryIDs) == 0 {
				return fmt.Errorf("at least one --entry flag is required")
			}

			cwd, err := os.Getwd()
			if err != nil {
				return err
			}

			jjRepo, err := jjinterface.LoadJJRepository(cwd)
			if err != nil {
				return fmt.Errorf("loading jj repository: %w", err)
			}

			gitRepo := jjRepo.GetGitRepository()

			// Parse entry IDs
			var hashes []gitinterface.Hash
			for _, idStr := range entryIDs {
				h, err := gitinterface.NewHash(idStr)
				if err != nil {
					return fmt.Errorf("invalid entry ID %q: %w", idStr, err)
				}
				hashes = append(hashes, h)
			}

			annotation := oslpkg.NewAnnotationEntry(hashes, skip, message)
			if err := annotation.Commit(gitRepo, false); err != nil {
				return fmt.Errorf("committing annotation: %w", err)
			}

			action := "annotated"
			if skip {
				action = "skipped"
			}
			cmd.Printf("Created annotation #%d (%s %d entries)\n", annotation.Number, action, len(entryIDs))

			return nil
		},
	}

	cmd.Flags().StringSliceVar(&entryIDs, "entry", nil, "OSL entry ID to annotate (can be specified multiple times)")
	cmd.Flags().BoolVar(&skip, "skip", false, "Mark referenced entries as skipped")
	cmd.Flags().StringVar(&message, "message", "", "Annotation message")

	return cmd
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
