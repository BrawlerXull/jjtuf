// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package osl

import (
	"github.com/jjtuf/jjtuf/pkg/gitinterface"
)

// GetLatestEntryOption configures how to search for OSL entries.
type GetLatestEntryOption func(*getLatestEntryOptions)

type getLatestEntryOptions struct {
	forBookmark string
	beforeEntry *OperationEntry
}

// ForBookmark filters entries to only those affecting the named bookmark.
func ForBookmark(bookmarkName string) GetLatestEntryOption {
	return func(o *getLatestEntryOptions) {
		o.forBookmark = bookmarkName
	}
}

// BeforeEntry limits search to entries before (older than) the given entry.
func BeforeEntry(entry *OperationEntry) GetLatestEntryOption {
	return func(o *getLatestEntryOptions) {
		o.beforeEntry = entry
	}
}

// ForReference is an alias for ForBookmark to match gittuf naming conventions.
func ForReference(refName string) GetLatestEntryOption {
	return ForBookmark(refName)
}

// GetLatestOperationEntryFor searches backwards through the OSL for the latest
// OperationEntry that affects the specified bookmark.
func GetLatestOperationEntryFor(repo *gitinterface.Repository, bookmarkName string) (*OperationEntry, error) {
	var result *OperationEntry

	err := IterateEntries(repo, func(entry Entry) bool {
		opEntry, ok := entry.(*OperationEntry)
		if !ok {
			return true // Skip non-operation entries
		}

		for _, delta := range opEntry.BookmarkDeltas {
			if delta.Name == bookmarkName {
				result = opEntry
				return false // Found it
			}
		}
		return true // Keep searching
	})

	if err != nil {
		return nil, err
	}

	if result == nil {
		return nil, ErrOSLEntryNotFound
	}

	return result, nil
}
