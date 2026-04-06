// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package gitinterface

import (
	"errors"
	"fmt"
	"strings"
)

var ErrTreeDoesNotHavePath = errors.New("tree does not contain specified path")

// EmptyTree returns the hash of an empty tree object.
func (r *Repository) EmptyTree() (Hash, error) {
	output, err := r.executor("hash-object", "-t", "tree", "--stdin")
	if err != nil {
		// Use the well-known empty tree hash
		return NewHash("4b825dc642cb6eb9a060e54bf899d69644b0bfe5")
	}
	return NewHash(strings.TrimSpace(output))
}

// GetAllFilesInTree returns all file paths and their blob hashes recursively.
func (r *Repository) GetAllFilesInTree(treeID Hash) (map[string]Hash, error) {
	output, err := r.executor("ls-tree", "-r", "--name-only", treeID.String())
	if err != nil {
		return nil, fmt.Errorf("listing tree: %w", err)
	}

	files := make(map[string]Hash)
	if strings.TrimSpace(output) == "" {
		return files, nil
	}

	// Get full ls-tree output with hashes
	fullOutput, err := r.executor("ls-tree", "-r", treeID.String())
	if err != nil {
		return nil, fmt.Errorf("listing tree with hashes: %w", err)
	}

	for _, line := range strings.Split(strings.TrimSpace(fullOutput), "\n") {
		if line == "" {
			continue
		}
		// Format: <mode> <type> <hash>\t<path>
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		fields := strings.Fields(parts[0])
		if len(fields) < 3 {
			continue
		}
		h, err := NewHash(fields[2])
		if err != nil {
			continue
		}
		files[parts[1]] = h
	}

	return files, nil
}

// GetPathIDInTree resolves a path within a tree and returns the object hash.
func (r *Repository) GetPathIDInTree(treePath string, treeID Hash) (Hash, error) {
	output, err := r.executor("ls-tree", treeID.String(), "--", treePath)
	if err != nil {
		return ZeroHash, fmt.Errorf("%w: %s", ErrTreeDoesNotHavePath, treePath)
	}

	line := strings.TrimSpace(output)
	if line == "" {
		return ZeroHash, fmt.Errorf("%w: %s", ErrTreeDoesNotHavePath, treePath)
	}

	// Format: <mode> <type> <hash>\t<path>
	parts := strings.SplitN(line, "\t", 2)
	if len(parts) < 1 {
		return ZeroHash, fmt.Errorf("%w: %s", ErrTreeDoesNotHavePath, treePath)
	}
	fields := strings.Fields(parts[0])
	if len(fields) < 3 {
		return ZeroHash, fmt.Errorf("%w: %s", ErrTreeDoesNotHavePath, treePath)
	}

	return NewHash(fields[2])
}

// TreeEntry represents an entry in a Git tree.
type TreeEntry struct {
	Name   string
	Mode   string // "100644" for blob, "040000" for tree
	GitID  Hash
	IsTree bool
}

// NewEntryBlob creates a TreeEntry for a blob.
func NewEntryBlob(name string, gitID Hash) TreeEntry {
	return TreeEntry{Name: name, Mode: "100644", GitID: gitID, IsTree: false}
}

// NewEntryTree creates a TreeEntry for a subtree.
func NewEntryTree(name string, gitID Hash) TreeEntry {
	return TreeEntry{Name: name, Mode: "040000", GitID: gitID, IsTree: true}
}

// TreeBuilder helps construct Git trees from entries.
type TreeBuilder struct {
	repo *Repository
}

// NewTreeBuilder creates a new TreeBuilder.
func NewTreeBuilder(repo *Repository) *TreeBuilder {
	return &TreeBuilder{repo: repo}
}

// WriteRootTreeFromBlobIDs creates a tree from a map of path -> blobID.
// Paths can contain slashes for nested directories (e.g., "a/b/c").
// Nested directories are created automatically as subtrees.
func (tb *TreeBuilder) WriteRootTreeFromBlobIDs(entries map[string]Hash) (Hash, error) {
	if len(entries) == 0 {
		return tb.repo.EmptyTree()
	}

	// Check if any paths have slashes (need nested tree building)
	hasNested := false
	for name := range entries {
		if strings.Contains(name, "/") {
			hasNested = true
			break
		}
	}

	if !hasNested {
		return tb.writeFlatTree(entries)
	}

	return tb.writeNestedTree(entries)
}

// writeFlatTree creates a single-level tree.
func (tb *TreeBuilder) writeFlatTree(entries map[string]Hash) (Hash, error) {
	var lines []string
	for name, blobID := range entries {
		lines = append(lines, fmt.Sprintf("100644 blob %s\t%s", blobID.String(), name))
	}

	input := strings.Join(lines, "\n")
	output, err := tb.repo.executorWithStdin(input, "mktree")
	if err != nil {
		return ZeroHash, fmt.Errorf("creating tree: %w", err)
	}

	return NewHash(strings.TrimSpace(output))
}

// writeNestedTree creates a tree with nested subdirectories.
// It groups entries by their top-level directory, recursively builds
// subtrees, and assembles them into the root tree.
func (tb *TreeBuilder) writeNestedTree(entries map[string]Hash) (Hash, error) {
	// Group entries: top-level blobs and subdirectory contents
	topBlobs := make(map[string]Hash)        // name -> blobID
	subdirs := make(map[string]map[string]Hash) // dirname -> {subpath -> blobID}

	for fullPath, blobID := range entries {
		slashIdx := strings.Index(fullPath, "/")
		if slashIdx < 0 {
			topBlobs[fullPath] = blobID
		} else {
			dirName := fullPath[:slashIdx]
			subPath := fullPath[slashIdx+1:]
			if subdirs[dirName] == nil {
				subdirs[dirName] = make(map[string]Hash)
			}
			subdirs[dirName][subPath] = blobID
		}
	}

	// Build each subdirectory tree recursively
	var lines []string
	for name, blobID := range topBlobs {
		lines = append(lines, fmt.Sprintf("100644 blob %s\t%s", blobID.String(), name))
	}

	for dirName, subEntries := range subdirs {
		subtreeID, err := tb.WriteRootTreeFromBlobIDs(subEntries)
		if err != nil {
			return ZeroHash, fmt.Errorf("creating subtree %s: %w", dirName, err)
		}
		lines = append(lines, fmt.Sprintf("040000 tree %s\t%s", subtreeID.String(), dirName))
	}

	input := strings.Join(lines, "\n")
	output, err := tb.repo.executorWithStdin(input, "mktree")
	if err != nil {
		return ZeroHash, fmt.Errorf("creating tree: %w", err)
	}

	return NewHash(strings.TrimSpace(output))
}
