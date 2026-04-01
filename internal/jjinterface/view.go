// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package jjinterface

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// JJView represents a parsed jj view (repository state snapshot).
type JJView struct {
	// HeadIDs are all commit head IDs.
	HeadIDs []string

	// WCCommitIDs maps workspace names to their working copy commit IDs.
	WCCommitIDs map[string]string

	// LocalBookmarks maps bookmark names to their targets.
	LocalBookmarks map[string]JJRefTarget

	// RemoteViews maps remote names to their state.
	RemoteViews map[string]JJRemoteView

	// GitRefs maps git ref names to their targets.
	GitRefs map[string]JJRefTarget
}

// JJRefTarget represents a jj ref target which can be in a conflict state.
type JJRefTarget struct {
	// Removes are commit IDs being removed (conflict sides).
	Removes []string
	// Adds are commit IDs being added.
	Adds []string
}

// IsConflict returns true if this ref target has conflicting values.
func (t JJRefTarget) IsConflict() bool {
	return len(t.Removes) > 0 || len(t.Adds) > 1
}

// ResolvedID returns the single commit ID if the target is resolved (not conflicted).
// Returns empty string if conflicted or absent.
func (t JJRefTarget) ResolvedID() string {
	if len(t.Removes) == 0 && len(t.Adds) == 1 {
		return t.Adds[0]
	}
	return ""
}

// IsAbsent returns true if the target represents an absent (deleted) bookmark.
func (t JJRefTarget) IsAbsent() bool {
	return len(t.Adds) == 0 && len(t.Removes) == 0
}

// JJRemoteView holds the state of a remote's bookmarks and tags.
type JJRemoteView struct {
	Bookmarks map[string]JJRemoteRef
	Tags      map[string]JJRemoteRef
}

// JJRemoteRef represents a remote bookmark or tag reference.
type JJRemoteRef struct {
	Target JJRefTarget
	State  string // "new" or "tracked"
}

// ReadView reads and parses a jj view from the op store.
func (r *JJRepository) ReadView(viewID string) (*JJView, error) {
	viewPath := filepath.Join(r.opStorePath, "views", viewID)
	data, err := os.ReadFile(viewPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrViewNotFound, err.Error())
	}

	return parseViewProto(data), nil
}

// parseViewProto does minimal protobuf parsing of a View message.
// View proto fields (from simple_op_store.proto):
//   1: head_ids (bytes, repeated)
//   2: wc_commit_id (bytes, deprecated)
//   5: bookmarks (Bookmark, repeated)
//   8: wc_commit_ids (map<string, bytes>)
//   3: git_refs (GitRef, repeated)
func parseViewProto(data []byte) *JJView {
	view := &JJView{
		WCCommitIDs:    make(map[string]string),
		LocalBookmarks: make(map[string]JJRefTarget),
		RemoteViews:    make(map[string]JJRemoteView),
		GitRefs:        make(map[string]JJRefTarget),
	}

	pos := 0
	for pos < len(data) {
		tag, n := decodeVarint(data[pos:])
		if n == 0 {
			break
		}
		pos += n

		fieldNumber := tag >> 3
		wireType := tag & 0x7

		switch wireType {
		case 0: // varint
			_, vn := decodeVarint(data[pos:])
			pos += vn
		case 2: // length-delimited
			length, ln := decodeVarint(data[pos:])
			if ln == 0 {
				return view
			}
			pos += ln
			if pos+int(length) > len(data) {
				return view
			}
			fieldData := data[pos : pos+int(length)]
			pos += int(length)

			switch fieldNumber {
			case 1: // head_ids
				view.HeadIDs = append(view.HeadIDs, hex.EncodeToString(fieldData))
			case 5: // bookmarks (Bookmark message)
				name, target := parseBookmarkProto(fieldData)
				if name != "" {
					view.LocalBookmarks[name] = target
				}
			case 3: // git_refs (GitRef message)
				name, target := parseGitRefProto(fieldData)
				if name != "" {
					view.GitRefs[name] = target
				}
			case 8: // wc_commit_ids (map entry)
				key, val := parseMapEntryProto(fieldData)
				if key != "" {
					view.WCCommitIDs[key] = hex.EncodeToString([]byte(val))
				}
			}
		default:
			// Skip fixed-width types
			return view
		}
	}

	return view
}

// parseBookmarkProto extracts name and local_target from a Bookmark message.
// Bookmark: field 1 = name (string), field 2 = local_target (RefTarget)
func parseBookmarkProto(data []byte) (string, JJRefTarget) {
	var name string
	var target JJRefTarget

	pos := 0
	for pos < len(data) {
		tag, n := decodeVarint(data[pos:])
		if n == 0 {
			break
		}
		pos += n

		fieldNumber := tag >> 3
		wireType := tag & 0x7

		if wireType == 2 {
			length, ln := decodeVarint(data[pos:])
			if ln == 0 {
				break
			}
			pos += ln
			if pos+int(length) > len(data) {
				break
			}
			fieldData := data[pos : pos+int(length)]
			pos += int(length)

			switch fieldNumber {
			case 1: // name
				name = string(fieldData)
			case 2: // local_target (RefTarget)
				target = parseRefTargetProto(fieldData)
			}
		} else if wireType == 0 {
			_, vn := decodeVarint(data[pos:])
			pos += vn
		} else {
			break
		}
	}

	return name, target
}

// parseGitRefProto extracts name and target from a GitRef message.
// GitRef: field 1 = name (string), field 3 = target (RefTarget)
func parseGitRefProto(data []byte) (string, JJRefTarget) {
	var name string
	var target JJRefTarget

	pos := 0
	for pos < len(data) {
		tag, n := decodeVarint(data[pos:])
		if n == 0 {
			break
		}
		pos += n

		fieldNumber := tag >> 3
		wireType := tag & 0x7

		if wireType == 2 {
			length, ln := decodeVarint(data[pos:])
			if ln == 0 {
				break
			}
			pos += ln
			if pos+int(length) > len(data) {
				break
			}
			fieldData := data[pos : pos+int(length)]
			pos += int(length)

			switch fieldNumber {
			case 1:
				name = string(fieldData)
			case 2: // commit_id (deprecated)
				target.Adds = append(target.Adds, hex.EncodeToString(fieldData))
			case 3: // target (RefTarget)
				target = parseRefTargetProto(fieldData)
			}
		} else if wireType == 0 {
			_, vn := decodeVarint(data[pos:])
			pos += vn
		} else {
			break
		}
	}

	return name, target
}

// parseRefTargetProto parses a RefTarget message.
// RefTarget: field 1 = commit_id (deprecated), field 3 = conflict (RefConflict)
func parseRefTargetProto(data []byte) JJRefTarget {
	var target JJRefTarget

	pos := 0
	for pos < len(data) {
		tag, n := decodeVarint(data[pos:])
		if n == 0 {
			break
		}
		pos += n

		fieldNumber := tag >> 3
		wireType := tag & 0x7

		if wireType == 2 {
			length, ln := decodeVarint(data[pos:])
			if ln == 0 {
				break
			}
			pos += ln
			if pos+int(length) > len(data) {
				break
			}
			fieldData := data[pos : pos+int(length)]
			pos += int(length)

			switch fieldNumber {
			case 1: // commit_id (deprecated simple form)
				target.Adds = []string{hex.EncodeToString(fieldData)}
			case 3: // conflict (RefConflict)
				target = parseRefConflictProto(fieldData)
			}
		} else if wireType == 0 {
			_, vn := decodeVarint(data[pos:])
			pos += vn
		} else {
			break
		}
	}

	return target
}

// parseRefConflictProto parses a RefConflict message.
// RefConflict: field 1 = removes (Term, repeated), field 2 = adds (Term, repeated)
// Term: field 1 = value (optional bytes)
func parseRefConflictProto(data []byte) JJRefTarget {
	var target JJRefTarget

	pos := 0
	for pos < len(data) {
		tag, n := decodeVarint(data[pos:])
		if n == 0 {
			break
		}
		pos += n

		fieldNumber := tag >> 3
		wireType := tag & 0x7

		if wireType == 2 {
			length, ln := decodeVarint(data[pos:])
			if ln == 0 {
				break
			}
			pos += ln
			if pos+int(length) > len(data) {
				break
			}
			fieldData := data[pos : pos+int(length)]
			pos += int(length)

			// Each Term is an embedded message with optional field 1 (bytes)
			termValue := parseTermProto(fieldData)
			switch fieldNumber {
			case 1: // removes
				if termValue != "" {
					target.Removes = append(target.Removes, termValue)
				}
			case 2: // adds
				target.Adds = append(target.Adds, termValue)
			}
		} else if wireType == 0 {
			_, vn := decodeVarint(data[pos:])
			pos += vn
		} else {
			break
		}
	}

	return target
}

// parseTermProto parses a RefConflict.Term message.
func parseTermProto(data []byte) string {
	pos := 0
	for pos < len(data) {
		tag, n := decodeVarint(data[pos:])
		if n == 0 {
			break
		}
		pos += n

		fieldNumber := tag >> 3
		wireType := tag & 0x7

		if wireType == 2 {
			length, ln := decodeVarint(data[pos:])
			if ln == 0 {
				break
			}
			pos += ln
			if pos+int(length) > len(data) {
				break
			}
			fieldData := data[pos : pos+int(length)]
			pos += int(length)

			if fieldNumber == 1 {
				return hex.EncodeToString(fieldData)
			}
		} else if wireType == 0 {
			_, vn := decodeVarint(data[pos:])
			pos += vn
		} else {
			break
		}
	}
	return ""
}

// parseMapEntryProto parses a protobuf map entry (key=string, value=bytes).
func parseMapEntryProto(data []byte) (string, string) {
	var key, val string

	pos := 0
	for pos < len(data) {
		tag, n := decodeVarint(data[pos:])
		if n == 0 {
			break
		}
		pos += n

		fieldNumber := tag >> 3
		wireType := tag & 0x7

		if wireType == 2 {
			length, ln := decodeVarint(data[pos:])
			if ln == 0 {
				break
			}
			pos += ln
			if pos+int(length) > len(data) {
				break
			}
			fieldData := data[pos : pos+int(length)]
			pos += int(length)

			switch fieldNumber {
			case 1:
				key = string(fieldData)
			case 2:
				val = string(fieldData)
			}
		} else if wireType == 0 {
			_, vn := decodeVarint(data[pos:])
			pos += vn
		} else {
			break
		}
	}

	return key, val
}
