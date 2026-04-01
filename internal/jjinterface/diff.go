// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package jjinterface

import (
	"github.com/jjtuf/jjtuf/internal/osl"
)

// ComputeBookmarkDeltas computes the bookmark changes between two views.
// oldView may be nil if this is the first operation being recorded.
func ComputeBookmarkDeltas(oldView, newView *JJView) []osl.BookmarkDelta {
	var deltas []osl.BookmarkDelta

	oldBookmarks := make(map[string]JJRefTarget)
	if oldView != nil {
		oldBookmarks = oldView.LocalBookmarks
	}

	// Check for new or modified bookmarks
	for name, newTarget := range newView.LocalBookmarks {
		oldTarget, existed := oldBookmarks[name]

		if !existed {
			// New bookmark
			deltas = append(deltas, osl.BookmarkDelta{
				Name:     name,
				FromID:   "",
				ToID:     newTarget.ResolvedID(),
				Conflict: newTarget.IsConflict(),
			})
			continue
		}

		// Check if bookmark changed
		oldResolved := oldTarget.ResolvedID()
		newResolved := newTarget.ResolvedID()

		if oldResolved != newResolved || oldTarget.IsConflict() != newTarget.IsConflict() {
			deltas = append(deltas, osl.BookmarkDelta{
				Name:     name,
				FromID:   oldResolved,
				ToID:     newResolved,
				Conflict: newTarget.IsConflict(),
			})
		}
	}

	// Check for deleted bookmarks
	for name, oldTarget := range oldBookmarks {
		if _, exists := newView.LocalBookmarks[name]; !exists {
			deltas = append(deltas, osl.BookmarkDelta{
				Name:   name,
				FromID: oldTarget.ResolvedID(),
				ToID:   "",
			})
		}
	}

	return deltas
}

// ShouldRecordOperation returns true if the operation should be recorded in
// the OSL. Ephemeral snapshot operations are filtered out.
func ShouldRecordOperation(op *JJOperation) bool {
	// Skip working copy snapshot operations
	if op.Metadata.IsSnapshot {
		return false
	}
	return true
}
