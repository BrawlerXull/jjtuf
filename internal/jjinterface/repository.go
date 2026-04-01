// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

// Package jjinterface provides functionality for interacting with Jujutsu (jj)
// repositories, including reading operations, views, and computing deltas.
package jjinterface

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jjtuf/jjtuf/pkg/gitinterface"
)

var (
	ErrNotAJJRepository  = errors.New("path is not a jj repository")
	ErrOperationNotFound = errors.New("jj operation not found")
	ErrViewNotFound      = errors.New("jj view not found")
	ErrNoOpHeads         = errors.New("no jj operation heads found")
)

// JJRepository represents a jj repository on disk.
type JJRepository struct {
	// gitRepo is the underlying Git repository used by jj's Git backend.
	gitRepo *gitinterface.Repository

	// jjRoot is the path to the .jj/ directory.
	jjRoot string

	// opStorePath is the path to the operation store.
	opStorePath string

	// storePath is the path to the backend store.
	storePath string
}

// LoadJJRepository opens an existing jj repository at the given path.
// It expects a .jj/ directory at the root.
func LoadJJRepository(workspacePath string) (*JJRepository, error) {
	jjRoot := filepath.Join(workspacePath, ".jj")
	if _, err := os.Stat(jjRoot); os.IsNotExist(err) {
		return nil, fmt.Errorf("%w: no .jj directory at %s", ErrNotAJJRepository, workspacePath)
	}

	// Determine op_store path
	opStorePath := filepath.Join(jjRoot, "repo", "op_store")
	if _, err := os.Stat(opStorePath); os.IsNotExist(err) {
		// Try alternate layout
		opStorePath = filepath.Join(jjRoot, "op_store")
		if _, err := os.Stat(opStorePath); os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: cannot find op_store", ErrNotAJJRepository)
		}
	}

	// Determine store path and underlying Git repo
	storePath := filepath.Join(jjRoot, "repo", "store")
	if _, err := os.Stat(storePath); os.IsNotExist(err) {
		storePath = filepath.Join(jjRoot, "store")
	}

	gitRepo, err := findGitBackend(storePath)
	if err != nil {
		return nil, fmt.Errorf("loading git backend: %w", err)
	}

	return &JJRepository{
		gitRepo:     gitRepo,
		jjRoot:      jjRoot,
		opStorePath: opStorePath,
		storePath:   storePath,
	}, nil
}

// GetGitRepository returns the underlying Git repository.
func (r *JJRepository) GetGitRepository() *gitinterface.Repository {
	return r.gitRepo
}

// GetJJRoot returns the path to the .jj/ directory.
func (r *JJRepository) GetJJRoot() string {
	return r.jjRoot
}

// GetOpHeadIDs reads the current operation head IDs from .jj/op_heads/.
func (r *JJRepository) GetOpHeadIDs() ([]string, error) {
	opHeadsDir := filepath.Join(r.jjRoot, "repo", "op_heads")
	if _, err := os.Stat(opHeadsDir); os.IsNotExist(err) {
		opHeadsDir = filepath.Join(r.jjRoot, "op_heads")
	}

	// jj stores op heads as files named by op ID in the op_heads/heads/ directory
	headsDir := filepath.Join(opHeadsDir, "heads")
	if _, err := os.Stat(headsDir); os.IsNotExist(err) {
		// Older jj versions: op head IDs are filenames directly in op_heads/
		headsDir = opHeadsDir
	}

	entries, err := os.ReadDir(headsDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrNoOpHeads, err.Error())
	}

	var headIDs []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Skip hidden files
		if len(name) > 0 && name[0] == '.' {
			continue
		}
		headIDs = append(headIDs, name)
	}

	if len(headIDs) == 0 {
		return nil, ErrNoOpHeads
	}

	return headIDs, nil
}

// findGitBackend locates and opens the Git repository used by jj's Git backend.
func findGitBackend(storePath string) (*gitinterface.Repository, error) {
	// Check for git_target file (points to external git repo)
	gitTargetFile := filepath.Join(storePath, "git_target")
	if data, err := os.ReadFile(gitTargetFile); err == nil {
		gitPath := string(data)
		gitPath = filepath.Clean(gitPath)
		if !filepath.IsAbs(gitPath) {
			gitPath = filepath.Join(storePath, gitPath)
		}
		return gitinterface.LoadRepository(gitPath)
	}

	// Check for git/ subdirectory (internal bare repo)
	gitDir := filepath.Join(storePath, "git")
	if _, err := os.Stat(gitDir); err == nil {
		return gitinterface.LoadRepository(gitDir)
	}

	// Check for colocated .git at workspace root
	// Walk up from storePath to find workspace root
	workspaceRoot := filepath.Dir(filepath.Dir(filepath.Dir(storePath))) // .jj/repo/store -> workspace
	dotGit := filepath.Join(workspaceRoot, ".git")
	if _, err := os.Stat(dotGit); err == nil {
		return gitinterface.LoadRepository(workspaceRoot)
	}

	return nil, fmt.Errorf("could not find git backend in %s", storePath)
}
