// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	cachePkg "github.com/jjtuf/jjtuf/internal/cache"
	"github.com/jjtuf/jjtuf/internal/jjinterface"
	"github.com/jjtuf/jjtuf/internal/osl"
)

// New creates the cache management command group.
func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Manage the verification cache",
	}

	cmd.AddCommand(populateCmd())
	cmd.AddCommand(deleteCmd())

	return cmd
}

func populateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "populate",
		Short: "Build the persistent verification cache",
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}

			jjRepo, err := jjinterface.LoadJJRepository(cwd)
			if err != nil {
				return fmt.Errorf("loading jj repository: %w", err)
			}

			cachePath := cachePkg.DefaultCachePath(jjRepo.GetJJRoot())
			persistent, err := cachePkg.NewPersistent(cachePath)
			if err != nil {
				return fmt.Errorf("creating cache: %w", err)
			}

			gitRepo := jjRepo.GetGitRepository()

			// Track latest entry per bookmark
			type entryInfo struct {
				id  string
				num uint64
			}
			bookmarkLatest := make(map[string]entryInfo)

			err = osl.IterateEntries(gitRepo, func(entry osl.Entry) bool {
				opEntry, ok := entry.(*osl.OperationEntry)
				if !ok {
					return true
				}

				for _, delta := range opEntry.BookmarkDeltas {
					existing, exists := bookmarkLatest[delta.Name]
					if !exists || opEntry.Number > existing.num {
						bookmarkLatest[delta.Name] = entryInfo{
							id:  opEntry.ID.String(),
							num: opEntry.Number,
						}
					}
				}
				return true
			})

			if err != nil {
				cmd.Println("No OSL entries found.")
				return nil
			}

			for bookmark, info := range bookmarkLatest {
				if err := persistent.SetLastVerifiedEntryForRef(bookmark, info.id, info.num); err != nil {
					return fmt.Errorf("caching entry for %s: %w", bookmark, err)
				}
				idShort := info.id
				if len(idShort) > 12 {
					idShort = idShort[:12]
				}
				cmd.Printf("  Cached: %s -> entry #%d (%s)\n", bookmark, info.num, idShort)
			}

			cmd.Printf("Cache populated with %d bookmarks at %s\n", len(bookmarkLatest), cachePath)
			return nil
		},
	}
}

func deleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete",
		Short: "Clear the verification cache",
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}

			jjRepo, err := jjinterface.LoadJJRepository(cwd)
			if err != nil {
				return fmt.Errorf("loading jj repository: %w", err)
			}

			cachePath := cachePkg.DefaultCachePath(jjRepo.GetJJRoot())
			persistent, err := cachePkg.NewPersistent(cachePath)
			if err != nil {
				return fmt.Errorf("loading cache: %w", err)
			}

			if err := persistent.Delete(); err != nil {
				if os.IsNotExist(err) {
					cmd.Println("No cache to delete.")
					return nil
				}
				return fmt.Errorf("deleting cache: %w", err)
			}

			cmd.Println("Verification cache deleted.")
			return nil
		},
	}
}
