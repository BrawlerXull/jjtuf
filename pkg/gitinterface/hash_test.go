// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package gitinterface

import (
	"testing"
)

func TestNewHash(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid SHA-1",
			input:   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
			wantErr: false,
		},
		{
			name:    "valid SHA-256",
			input:   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: false,
		},
		{
			name:    "invalid hex",
			input:   "notahex",
			wantErr: true,
		},
		{
			name:    "wrong length",
			input:   "deadbeef",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := NewHash(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewHash(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && tt.input != "" && h.String() != tt.input {
				t.Errorf("round-trip failed: got %q, want %q", h.String(), tt.input)
			}
		})
	}
}

func TestHashIsZero(t *testing.T) {
	zero := ZeroHash
	if !zero.IsZero() {
		t.Error("ZeroHash should be zero")
	}

	nonZero, _ := NewHash("da39a3ee5e6b4b0d3255bfef95601890afd80709")
	if nonZero.IsZero() {
		t.Error("non-zero hash reported as zero")
	}
}

func TestHashEqual(t *testing.T) {
	h1, _ := NewHash("da39a3ee5e6b4b0d3255bfef95601890afd80709")
	h2, _ := NewHash("da39a3ee5e6b4b0d3255bfef95601890afd80709")
	h3, _ := NewHash("4b825dc642cb6eb9a060e54bf899d69644b0bfe5")

	if !h1.Equal(h2) {
		t.Error("equal hashes reported as unequal")
	}
	if h1.Equal(h3) {
		t.Error("different hashes reported as equal")
	}
	if h1.Equal(ZeroHash) {
		t.Error("hash equals zero hash unexpectedly")
	}
}
