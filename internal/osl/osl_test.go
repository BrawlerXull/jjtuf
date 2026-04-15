// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package osl

import (
	"testing"
)

func TestNewOperationEntry(t *testing.T) {
	deltas := []BookmarkDelta{
		{Name: "main", FromID: "abc", ToID: "def"},
	}
	entry := NewOperationEntry("op123", []string{"parent1"}, "digest456", deltas)

	if entry.OperationID != "op123" {
		t.Errorf("wrong operation ID: %s", entry.OperationID)
	}
	if len(entry.ParentOpIDs) != 1 || entry.ParentOpIDs[0] != "parent1" {
		t.Error("wrong parent IDs")
	}
	if entry.ViewDigest != "digest456" {
		t.Errorf("wrong view digest: %s", entry.ViewDigest)
	}
	if len(entry.BookmarkDeltas) != 1 {
		t.Error("wrong bookmark deltas count")
	}
}

func TestOperationEntryCommitMessage(t *testing.T) {
	deltas := []BookmarkDelta{
		{Name: "main", FromID: "abc123", ToID: "def456"},
		{Name: "feature", FromID: "", ToID: "xyz789", Conflict: true},
	}
	entry := NewOperationEntry("opid001", []string{"parent1", "parent2"}, "viewdigest", deltas)
	entry.Number = 5

	msg, err := entry.createCommitMessage(true)
	if err != nil {
		t.Fatalf("createCommitMessage: %v", err)
	}

	// Check header
	lines := splitLines(msg)
	if lines[0] != OperationEntryHeader {
		t.Errorf("wrong header: %q", lines[0])
	}

	// Check it contains key fields
	checkContains(t, msg, OperationIDKey+": opid001")
	checkContains(t, msg, ViewDigestKey+": viewdigest")
	checkContains(t, msg, "parent1,parent2")
	checkContains(t, msg, "main:abc123:def456")
	checkContains(t, msg, "feature::xyz789:conflict")
	checkContains(t, msg, NumberKey+": 5")
}

func TestOperationEntryParseRoundTrip(t *testing.T) {
	deltas := []BookmarkDelta{
		{Name: "main", FromID: "aaaa", ToID: "bbbb"},
	}
	entry := NewOperationEntry("myopid", []string{"parentA"}, "mydigest", deltas)
	entry.Number = 3

	msg, err := entry.createCommitMessage(true)
	if err != nil {
		t.Fatalf("createCommitMessage: %v", err)
	}

	// Parse it back (using nil hash since we're unit testing)
	parsed, err := parseEntry(nil, msg)
	if err != nil {
		t.Fatalf("parseEntry: %v", err)
	}

	opEntry, ok := parsed.(*OperationEntry)
	if !ok {
		t.Fatalf("expected *OperationEntry, got %T", parsed)
	}

	if opEntry.OperationID != "myopid" {
		t.Errorf("wrong operation ID: %s", opEntry.OperationID)
	}
	if opEntry.ViewDigest != "mydigest" {
		t.Errorf("wrong view digest: %s", opEntry.ViewDigest)
	}
	if opEntry.Number != 3 {
		t.Errorf("wrong number: %d", opEntry.Number)
	}
	if len(opEntry.BookmarkDeltas) != 1 {
		t.Fatalf("wrong delta count: %d", len(opEntry.BookmarkDeltas))
	}
	if opEntry.BookmarkDeltas[0].Name != "main" {
		t.Errorf("wrong bookmark name: %s", opEntry.BookmarkDeltas[0].Name)
	}
}

func TestAnnotationEntry(t *testing.T) {
	annotation := NewAnnotationEntry(nil, true, "revoke this")

	if !annotation.Skip {
		t.Error("expected skip=true")
	}
	if annotation.Message != "revoke this" {
		t.Errorf("wrong message: %s", annotation.Message)
	}
}

func TestAnnotationRefersTo(t *testing.T) {
	// We can't create real hashes without a repo, but we can test the logic
	annotation := NewAnnotationEntry(nil, false, "")

	// RefersTo on empty should return false
	if annotation.RefersTo(nil) {
		t.Error("expected false for empty entry IDs")
	}
}

func TestAnnotationCommitMessage(t *testing.T) {
	annotation := NewAnnotationEntry(nil, true, "test message")
	annotation.Number = 7

	msg, err := annotation.createCommitMessage(true)
	if err != nil {
		t.Fatalf("createCommitMessage: %v", err)
	}

	lines := splitLines(msg)
	if lines[0] != AnnotationEntryHeader {
		t.Errorf("wrong header: %q", lines[0])
	}
	checkContains(t, msg, SkipKey+": true")
	checkContains(t, msg, NumberKey+": 7")
	// Message is PEM-encoded — verify the PEM block is present
	checkContains(t, msg, BeginMessage)
	checkContains(t, msg, EndMessage)
}

func TestBookmarkDeltaConflict(t *testing.T) {
	delta := BookmarkDelta{
		Name:     "main",
		FromID:   "old",
		ToID:     "new",
		Conflict: true,
	}

	entry := NewOperationEntry("op", nil, "digest", []BookmarkDelta{delta})
	msg, _ := entry.createCommitMessage(false)
	checkContains(t, msg, "main:old:new:conflict")
}

func TestBookmarkDeltaNewBookmark(t *testing.T) {
	delta := BookmarkDelta{Name: "fresh", FromID: "", ToID: "abc123"}
	entry := NewOperationEntry("op", nil, "d", []BookmarkDelta{delta})
	msg, _ := entry.createCommitMessage(false)
	checkContains(t, msg, "fresh::abc123")
}

func TestBookmarkDeltaDeletedBookmark(t *testing.T) {
	delta := BookmarkDelta{Name: "gone", FromID: "abc123", ToID: ""}
	entry := NewOperationEntry("op", nil, "d", []BookmarkDelta{delta})
	msg, _ := entry.createCommitMessage(false)
	checkContains(t, msg, "gone:abc123:")
}

func TestParseInvalidEntry(t *testing.T) {
	_, err := parseEntry(nil, "")
	if err == nil {
		t.Error("expected error for empty message")
	}

	_, err = parseEntry(nil, "UNKNOWN HEADER\n\nkey: value")
	if err == nil {
		t.Error("expected error for unknown header")
	}
}

// helpers

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func checkContains(t *testing.T, haystack, needle string) {
	t.Helper()
	if !containsString(haystack, needle) {
		t.Errorf("expected to find %q in:\n%s", needle, haystack)
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		})())
}
