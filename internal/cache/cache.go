// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

// Package cache provides a persistent verification cache for jjtuf.
// It stores the last verified OSL entry per bookmark to avoid redundant
// re-verification of already-checked history.
package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var ErrCacheNotFound = errors.New("cache not found")

// Persistent stores verification results on disk.
type Persistent struct {
	mu       sync.RWMutex
	filePath string
	data     CacheData
}

// CacheData is the serialized cache format.
type CacheData struct {
	// LastVerifiedEntries maps bookmark names to their last verified OSL entry.
	LastVerifiedEntries map[string]VerifiedEntry `json:"lastVerifiedEntries"`
}

// VerifiedEntry records the last verified OSL entry for a bookmark.
type VerifiedEntry struct {
	// EntryID is the Git hash of the OSL entry commit.
	EntryID string `json:"entryID"`

	// EntryNumber is the OSL entry sequence number.
	EntryNumber uint64 `json:"entryNumber"`
}

// NewPersistent creates or loads a persistent cache at the given path.
func NewPersistent(cachePath string) (*Persistent, error) {
	p := &Persistent{
		filePath: cachePath,
		data: CacheData{
			LastVerifiedEntries: make(map[string]VerifiedEntry),
		},
	}

	// Try to load existing cache
	if data, err := os.ReadFile(cachePath); err == nil {
		if err := json.Unmarshal(data, &p.data); err != nil {
			// Corrupt cache — start fresh
			p.data.LastVerifiedEntries = make(map[string]VerifiedEntry)
		}
	}

	return p, nil
}

// GetLastVerifiedEntryForRef returns the last verified entry for a bookmark.
// Returns (0, "") if no verified entry exists.
func (p *Persistent) GetLastVerifiedEntryForRef(bookmarkName string) (uint64, string) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, exists := p.data.LastVerifiedEntries[bookmarkName]
	if !exists {
		return 0, ""
	}

	return entry.EntryNumber, entry.EntryID
}

// SetLastVerifiedEntryForRef records a verified entry for a bookmark.
func (p *Persistent) SetLastVerifiedEntryForRef(bookmarkName, entryID string, entryNumber uint64) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.data.LastVerifiedEntries[bookmarkName] = VerifiedEntry{
		EntryID:     entryID,
		EntryNumber: entryNumber,
	}

	return p.save()
}

// Clear removes all cached entries.
func (p *Persistent) Clear() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.data.LastVerifiedEntries = make(map[string]VerifiedEntry)
	return p.save()
}

// save writes the cache to disk.
func (p *Persistent) save() error {
	data, err := json.MarshalIndent(p.data, "", "  ")
	if err != nil {
		return fmt.Errorf("serializing cache: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(p.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}

	return os.WriteFile(p.filePath, data, 0644)
}

// Delete removes the cache file from disk.
func (p *Persistent) Delete() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.data.LastVerifiedEntries = make(map[string]VerifiedEntry)
	return os.Remove(p.filePath)
}

// DefaultCachePath returns the default cache file path for a jj repository.
func DefaultCachePath(jjRoot string) string {
	return filepath.Join(jjRoot, "jjtuf-cache.json")
}
