// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package gitinterface

import (
	"encoding/hex"
	"errors"
	"fmt"
)

var (
	ErrInvalidHashEncoding = errors.New("invalid hash encoding")
	ErrInvalidHashLength   = errors.New("invalid hash length")
)

// Hash represents a Git object hash (SHA-1 or SHA-256).
type Hash []byte

// ZeroHash is the zero-value hash used as a sentinel.
var ZeroHash = Hash{}

// NewHash creates a Hash from a hex-encoded string.
func NewHash(h string) (Hash, error) {
	if len(h) == 0 {
		return ZeroHash, nil
	}

	hashBytes, err := hex.DecodeString(h)
	if err != nil {
		return ZeroHash, fmt.Errorf("%w: %s", ErrInvalidHashEncoding, err.Error())
	}

	// SHA-1 = 20 bytes, SHA-256 = 32 bytes
	if len(hashBytes) != 20 && len(hashBytes) != 32 {
		return ZeroHash, fmt.Errorf("%w: expected 20 or 32 bytes, got %d", ErrInvalidHashLength, len(hashBytes))
	}

	return Hash(hashBytes), nil
}

// String returns the hex-encoded representation of the hash.
func (h Hash) String() string {
	return hex.EncodeToString(h)
}

// IsZero returns true if the hash is the zero hash.
func (h Hash) IsZero() bool {
	if len(h) == 0 {
		return true
	}
	for _, b := range h {
		if b != 0 {
			return false
		}
	}
	return true
}

// Equal returns true if two hashes are identical.
func (h Hash) Equal(other Hash) bool {
	if len(h) != len(other) {
		return false
	}
	for i := range h {
		if h[i] != other[i] {
			return false
		}
	}
	return true
}
