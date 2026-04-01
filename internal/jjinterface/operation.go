// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package jjinterface

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// JJOperation represents a parsed jj operation.
type JJOperation struct {
	// ID is the operation ID (BLAKE2b-512 hash hex, used as filename).
	ID string

	// ViewID is the ID of the View snapshot this operation produced.
	ViewID string

	// ParentIDs are the parent operation IDs.
	ParentIDs []string

	// Metadata contains operation metadata.
	Metadata JJOperationMetadata

	// CommitPredecessors maps new commit IDs to their predecessor commit IDs.
	CommitPredecessors map[string][]string
}

// JJOperationMetadata contains metadata about an operation.
type JJOperationMetadata struct {
	StartTime     time.Time
	EndTime       time.Time
	Description   string
	Hostname      string
	Username      string
	IsSnapshot    bool
	WorkspaceName string
	Tags          map[string]string
}

// ReadOperation reads and parses a jj operation from the op store.
// For the MVP, we read the raw protobuf bytes and extract key fields.
// Full protobuf parsing will be added when proto generation is set up.
func (r *JJRepository) ReadOperation(opID string) (*JJOperation, error) {
	opPath := filepath.Join(r.opStorePath, "operations", opID)
	data, err := os.ReadFile(opPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrOperationNotFound, err.Error())
	}

	// For now, store raw data and extract what we can.
	// Full protobuf parsing requires generated Go code from simple_op_store.proto.
	op := &JJOperation{
		ID:                 opID,
		CommitPredecessors: make(map[string][]string),
	}

	// Parse the protobuf minimally using wire format.
	// This is a temporary approach until proper proto generation is set up.
	op.ViewID, op.ParentIDs, op.Metadata = parseOperationProto(data)

	return op, nil
}

// ReadOperationRaw reads the raw bytes of an operation for hashing.
func (r *JJRepository) ReadOperationRaw(opID string) ([]byte, error) {
	opPath := filepath.Join(r.opStorePath, "operations", opID)
	return os.ReadFile(opPath)
}

// ReadViewRaw reads the raw bytes of a view for hashing.
func (r *JJRepository) ReadViewRaw(viewID string) ([]byte, error) {
	viewPath := filepath.Join(r.opStorePath, "views", viewID)
	return os.ReadFile(viewPath)
}

// ComputeViewDigest computes the SHA-256 digest of a view's raw bytes.
func (r *JJRepository) ComputeViewDigest(viewID string) (string, error) {
	data, err := r.ReadViewRaw(viewID)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrViewNotFound, err.Error())
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// parseOperationProto does minimal protobuf wire-format parsing.
// This extracts view_id (field 1), parents (field 2), and metadata (field 3)
// without requiring generated protobuf code.
//
// Wire format:
//   field 1 (view_id): tag = 0x0a (field 1, wire type 2 = length-delimited)
//   field 2 (parents): tag = 0x12 (field 2, wire type 2)
//   field 3 (metadata): tag = 0x1a (field 3, wire type 2)
func parseOperationProto(data []byte) (viewID string, parentIDs []string, metadata JJOperationMetadata) {
	pos := 0
	for pos < len(data) {
		if pos >= len(data) {
			break
		}

		// Read tag (varint)
		tag, n := decodeVarint(data[pos:])
		if n == 0 {
			break
		}
		pos += n

		fieldNumber := tag >> 3
		wireType := tag & 0x7

		switch wireType {
		case 0: // varint
			_, n := decodeVarint(data[pos:])
			pos += n
		case 2: // length-delimited
			length, n := decodeVarint(data[pos:])
			if n == 0 {
				return
			}
			pos += n

			if pos+int(length) > len(data) {
				return
			}

			fieldData := data[pos : pos+int(length)]
			pos += int(length)

			switch fieldNumber {
			case 1: // view_id (bytes)
				viewID = hex.EncodeToString(fieldData)
			case 2: // parents (bytes, repeated)
				parentIDs = append(parentIDs, hex.EncodeToString(fieldData))
			case 3: // metadata (embedded message)
				metadata = parseMetadataProto(fieldData)
			}
		default:
			// Skip unknown wire types
			return
		}
	}

	return
}

// parseMetadataProto extracts fields from the OperationMetadata message.
func parseMetadataProto(data []byte) JJOperationMetadata {
	var meta JJOperationMetadata
	meta.Tags = make(map[string]string)

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
			val, n := decodeVarint(data[pos:])
			pos += n
			switch fieldNumber {
			case 7: // is_snapshot
				meta.IsSnapshot = val != 0
			}
		case 2: // length-delimited
			length, n := decodeVarint(data[pos:])
			if n == 0 {
				return meta
			}
			pos += n
			if pos+int(length) > len(data) {
				return meta
			}
			fieldData := data[pos : pos+int(length)]
			pos += int(length)

			switch fieldNumber {
			case 3: // description
				meta.Description = string(fieldData)
			case 4: // hostname
				meta.Hostname = string(fieldData)
			case 5: // username
				meta.Username = string(fieldData)
			case 8: // workspace_name (optional string)
				meta.WorkspaceName = string(fieldData)
			}
		default:
			return meta
		}
	}

	return meta
}

// decodeVarint decodes a protobuf varint from a byte slice.
// Returns the value and the number of bytes consumed.
func decodeVarint(data []byte) (uint64, int) {
	var val uint64
	var shift uint
	for i, b := range data {
		val |= uint64(b&0x7F) << shift
		if b < 0x80 {
			return val, i + 1
		}
		shift += 7
		if shift >= 64 {
			return 0, 0
		}
	}
	return 0, 0
}
