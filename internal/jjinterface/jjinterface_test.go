// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package jjinterface

import (
	"encoding/hex"
	"testing"
)

// ---------------------------------------------------------------------------
// Proto encoding helpers (no external dependencies)
// ---------------------------------------------------------------------------

// varint encodes v as a protobuf varint.
func varint(v uint64) []byte {
	var buf []byte
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	buf = append(buf, byte(v))
	return buf
}

// fieldLen encodes a length-delimited field (wire type 2).
// tag = (fieldNumber << 3) | 2
func fieldLen(num uint64, data []byte) []byte {
	tag := (num << 3) | 2
	out := varint(tag)
	out = append(out, varint(uint64(len(data)))...)
	out = append(out, data...)
	return out
}

// fieldVarint encodes a varint field (wire type 0).
// tag = (fieldNumber << 3) | 0
func fieldVarint(num uint64, v uint64) []byte {
	tag := num << 3 // wire type 0
	out := varint(tag)
	out = append(out, varint(v)...)
	return out
}

// concat joins byte slices.
func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ---------------------------------------------------------------------------
// decodeVarint tests
// ---------------------------------------------------------------------------

func TestDecodeVarint(t *testing.T) {
	t.Run("single byte", func(t *testing.T) {
		val, n := decodeVarint([]byte{0x05})
		if val != 5 || n != 1 {
			t.Errorf("got val=%d n=%d, want 5 1", val, n)
		}
	})

	t.Run("multi byte", func(t *testing.T) {
		// 300 in varint: 0xAC 0x02
		val, n := decodeVarint([]byte{0xAC, 0x02})
		if val != 300 || n != 2 {
			t.Errorf("got val=%d n=%d, want 300 2", val, n)
		}
	})

	t.Run("max 7 byte", func(t *testing.T) {
		// encode 2^49-1 (requires 7 bytes): each byte sets continuation bit
		enc := varint(1 << 49)
		val, n := decodeVarint(enc)
		if val != 1<<49 || n != len(enc) {
			t.Errorf("got val=%d n=%d, want %d %d", val, n, uint64(1<<49), len(enc))
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		val, n := decodeVarint([]byte{})
		if val != 0 || n != 0 {
			t.Errorf("got val=%d n=%d, want 0 0", val, n)
		}
	})
}

// ---------------------------------------------------------------------------
// parseOperationProto tests
// ---------------------------------------------------------------------------

func TestParseOperationProto(t *testing.T) {
	// viewID: 4 raw bytes → should come back as 8-char hex
	rawViewID := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	expectedViewID := hex.EncodeToString(rawViewID) // "deadbeef"

	// two parent IDs
	parent1 := []byte{0x01, 0x02, 0x03, 0x04}
	parent2 := []byte{0x05, 0x06, 0x07, 0x08}

	// metadata with description + hostname + is_snapshot=true
	metaData := concat(
		fieldLen(3, []byte("test commit")), // description (field 3)
		fieldLen(4, []byte("myhost")),      // hostname (field 4)
		fieldVarint(7, 1),                  // is_snapshot = true (field 7)
	)

	data := concat(
		fieldLen(1, rawViewID),   // view_id (field 1)
		fieldLen(2, parent1),     // parent (field 2)
		fieldLen(2, parent2),     // parent (field 2) repeated
		fieldLen(3, metaData),    // metadata (field 3)
	)

	viewID, parentIDs, meta := parseOperationProto(data)

	if viewID != expectedViewID {
		t.Errorf("viewID = %q, want %q", viewID, expectedViewID)
	}
	if len(parentIDs) != 2 {
		t.Fatalf("len(parentIDs) = %d, want 2", len(parentIDs))
	}
	if parentIDs[0] != hex.EncodeToString(parent1) {
		t.Errorf("parentIDs[0] = %q, want %q", parentIDs[0], hex.EncodeToString(parent1))
	}
	if parentIDs[1] != hex.EncodeToString(parent2) {
		t.Errorf("parentIDs[1] = %q, want %q", parentIDs[1], hex.EncodeToString(parent2))
	}
	if meta.Description != "test commit" {
		t.Errorf("Description = %q, want %q", meta.Description, "test commit")
	}
	if meta.Hostname != "myhost" {
		t.Errorf("Hostname = %q, want %q", meta.Hostname, "myhost")
	}
	if !meta.IsSnapshot {
		t.Error("IsSnapshot should be true")
	}
}

func TestParseOperationProtoSnapshot(t *testing.T) {
	// Only metadata with is_snapshot=true (field 7, varint 1)
	metaData := fieldVarint(7, 1) // tag=0x38, value=0x01

	data := fieldLen(3, metaData)

	_, _, meta := parseOperationProto(data)
	if !meta.IsSnapshot {
		t.Error("IsSnapshot should be true when field 7 varint=1")
	}
}

// ---------------------------------------------------------------------------
// parseViewProto tests
// ---------------------------------------------------------------------------

func TestParseViewProtoEmpty(t *testing.T) {
	view := parseViewProto([]byte{})
	if view == nil {
		t.Fatal("expected non-nil view")
	}
	if len(view.HeadIDs) != 0 {
		t.Errorf("expected 0 head IDs, got %d", len(view.HeadIDs))
	}
	if len(view.LocalBookmarks) != 0 {
		t.Errorf("expected 0 local bookmarks, got %d", len(view.LocalBookmarks))
	}
}

func TestParseViewProtoWithHeads(t *testing.T) {
	headID := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	data := fieldLen(1, headID) // head_ids (field 1)

	view := parseViewProto(data)
	if len(view.HeadIDs) != 1 {
		t.Fatalf("expected 1 head ID, got %d", len(view.HeadIDs))
	}
	if view.HeadIDs[0] != hex.EncodeToString(headID) {
		t.Errorf("HeadIDs[0] = %q, want %q", view.HeadIDs[0], hex.EncodeToString(headID))
	}
}

func TestParseViewProtoWithBookmark(t *testing.T) {
	commitID := []byte{0x11, 0x22, 0x33, 0x44}

	// RefTarget: field 1 = commit_id bytes (deprecated simple form)
	refTarget := fieldLen(1, commitID)

	// Bookmark: field 1 = name, field 2 = local_target
	bookmark := concat(
		fieldLen(1, []byte("main")), // name
		fieldLen(2, refTarget),      // local_target
	)

	// View: field 5 = bookmarks (repeated)
	data := fieldLen(5, bookmark)

	view := parseViewProto(data)
	target, ok := view.LocalBookmarks["main"]
	if !ok {
		t.Fatal("expected bookmark 'main' to exist")
	}
	if len(target.Adds) != 1 {
		t.Fatalf("expected 1 Add, got %d", len(target.Adds))
	}
	if target.IsConflict() {
		t.Error("expected IsConflict() == false")
	}
	if target.ResolvedID() == "" {
		t.Error("expected non-empty ResolvedID()")
	}
	if target.ResolvedID() != hex.EncodeToString(commitID) {
		t.Errorf("ResolvedID() = %q, want %q", target.ResolvedID(), hex.EncodeToString(commitID))
	}
}

func TestParseViewProtoWithConflictBookmark(t *testing.T) {
	removeID := []byte{0x01, 0x02, 0x03, 0x04}
	addID1 := []byte{0x05, 0x06, 0x07, 0x08}
	addID2 := []byte{0x09, 0x0A, 0x0B, 0x0C}

	// Term: field 1 = value (bytes)
	termRemove := fieldLen(1, removeID)
	termAdd1 := fieldLen(1, addID1)
	termAdd2 := fieldLen(1, addID2)

	// RefConflict: field 1 = removes (Term), field 2 = adds (Term)
	refConflict := concat(
		fieldLen(1, termRemove), // removes
		fieldLen(2, termAdd1),   // adds
		fieldLen(2, termAdd2),   // adds (second)
	)

	// RefTarget: field 3 = conflict (RefConflict)
	refTarget := fieldLen(3, refConflict)

	// Bookmark: field 1 = name, field 2 = local_target
	bookmark := concat(
		fieldLen(1, []byte("feature")),
		fieldLen(2, refTarget),
	)

	// View: field 5 = bookmarks
	data := fieldLen(5, bookmark)

	view := parseViewProto(data)
	target, ok := view.LocalBookmarks["feature"]
	if !ok {
		t.Fatal("expected bookmark 'feature' to exist")
	}
	if !target.IsConflict() {
		t.Error("expected IsConflict() == true")
	}
	if len(target.Removes) != 1 {
		t.Errorf("expected 1 Remove, got %d", len(target.Removes))
	}
	if len(target.Adds) != 2 {
		t.Errorf("expected 2 Adds, got %d", len(target.Adds))
	}
}

// ---------------------------------------------------------------------------
// ComputeBookmarkDeltas tests
// ---------------------------------------------------------------------------

func makeView(bookmarks map[string]string) *JJView {
	v := &JJView{
		WCCommitIDs:    make(map[string]string),
		LocalBookmarks: make(map[string]JJRefTarget),
		RemoteViews:    make(map[string]JJRemoteView),
		GitRefs:        make(map[string]JJRefTarget),
	}
	for name, id := range bookmarks {
		v.LocalBookmarks[name] = JJRefTarget{Adds: []string{id}}
	}
	return v
}

func makeConflictView(name, removeID, addID1, addID2 string) *JJView {
	v := &JJView{
		WCCommitIDs:    make(map[string]string),
		LocalBookmarks: make(map[string]JJRefTarget),
		RemoteViews:    make(map[string]JJRemoteView),
		GitRefs:        make(map[string]JJRefTarget),
	}
	v.LocalBookmarks[name] = JJRefTarget{
		Removes: []string{removeID},
		Adds:    []string{addID1, addID2},
	}
	return v
}

func TestComputeBookmarkDeltasNewBookmark(t *testing.T) {
	newView := makeView(map[string]string{"main": "abc123"})
	deltas := ComputeBookmarkDeltas(nil, newView)

	if len(deltas) != 1 {
		t.Fatalf("expected 1 delta, got %d", len(deltas))
	}
	d := deltas[0]
	if d.Name != "main" {
		t.Errorf("Name = %q, want %q", d.Name, "main")
	}
	if d.FromID != "" {
		t.Errorf("FromID = %q, want empty", d.FromID)
	}
	if d.ToID != "abc123" {
		t.Errorf("ToID = %q, want %q", d.ToID, "abc123")
	}
}

func TestComputeBookmarkDeltasUpdated(t *testing.T) {
	oldView := makeView(map[string]string{"main": "commitA"})
	newView := makeView(map[string]string{"main": "commitB"})
	deltas := ComputeBookmarkDeltas(oldView, newView)

	if len(deltas) != 1 {
		t.Fatalf("expected 1 delta, got %d", len(deltas))
	}
	d := deltas[0]
	if d.FromID != "commitA" {
		t.Errorf("FromID = %q, want %q", d.FromID, "commitA")
	}
	if d.ToID != "commitB" {
		t.Errorf("ToID = %q, want %q", d.ToID, "commitB")
	}
}

func TestComputeBookmarkDeltasDeleted(t *testing.T) {
	oldView := makeView(map[string]string{"main": "commitA"})
	newView := makeView(map[string]string{})
	deltas := ComputeBookmarkDeltas(oldView, newView)

	if len(deltas) != 1 {
		t.Fatalf("expected 1 delta, got %d", len(deltas))
	}
	d := deltas[0]
	if d.Name != "main" {
		t.Errorf("Name = %q, want %q", d.Name, "main")
	}
	if d.FromID != "commitA" {
		t.Errorf("FromID = %q, want %q", d.FromID, "commitA")
	}
	if d.ToID != "" {
		t.Errorf("ToID = %q, want empty", d.ToID)
	}
}

func TestComputeBookmarkDeltasNoChange(t *testing.T) {
	oldView := makeView(map[string]string{"main": "commitA"})
	newView := makeView(map[string]string{"main": "commitA"})
	deltas := ComputeBookmarkDeltas(oldView, newView)

	if len(deltas) != 0 {
		t.Errorf("expected 0 deltas, got %d", len(deltas))
	}
}

func TestComputeBookmarkDeltasConflict(t *testing.T) {
	oldView := makeView(map[string]string{"main": "commitA"})
	newView := makeConflictView("main", "commitA", "commitB", "commitC")
	deltas := ComputeBookmarkDeltas(oldView, newView)

	if len(deltas) != 1 {
		t.Fatalf("expected 1 delta, got %d", len(deltas))
	}
	d := deltas[0]
	if !d.Conflict {
		t.Error("expected Conflict == true")
	}
}

// ---------------------------------------------------------------------------
// ShouldRecordOperation tests
// ---------------------------------------------------------------------------

func TestShouldRecordOperation(t *testing.T) {
	t.Run("non-snapshot should record", func(t *testing.T) {
		op := &JJOperation{
			Metadata: JJOperationMetadata{IsSnapshot: false},
		}
		if !ShouldRecordOperation(op) {
			t.Error("expected ShouldRecordOperation == true for non-snapshot")
		}
	})

	t.Run("snapshot should not record", func(t *testing.T) {
		op := &JJOperation{
			Metadata: JJOperationMetadata{IsSnapshot: true},
		}
		if ShouldRecordOperation(op) {
			t.Error("expected ShouldRecordOperation == false for snapshot")
		}
	})
}
