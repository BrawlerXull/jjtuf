// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package gitinterface

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var (
	ErrRepositoryPathNotSpecified = errors.New("repository path not specified")
	ErrNotAGitRepository          = errors.New("path is not a Git repository")
)

// Repository provides an abstraction over a Git repository.
type Repository struct {
	gitDirPath string // Path to the .git directory (or bare repo root)
}

// LoadRepository opens an existing Git repository at the given path.
// The path can point to a working tree or directly to a .git directory.
func LoadRepository(repositoryPath string) (*Repository, error) {
	if repositoryPath == "" {
		return nil, ErrRepositoryPathNotSpecified
	}

	// Resolve the git directory
	gitDir, err := resolveGitDir(repositoryPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrNotAGitRepository, err.Error())
	}

	return &Repository{gitDirPath: gitDir}, nil
}

// GetGitDir returns the path to the .git directory.
func (r *Repository) GetGitDir() string {
	return r.gitDirPath
}

// IsBare returns true if the repository is bare.
func (r *Repository) IsBare() bool {
	output, err := r.executor("rev-parse", "--is-bare-repository")
	if err != nil {
		return false
	}
	return strings.TrimSpace(output) == "true"
}

// executor runs a git command in the repository context and returns its stdout.
func (r *Repository) executor(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = r.gitDirPath
	cmd.Env = append(os.Environ(), "GIT_DIR="+r.gitDirPath, "LC_ALL=C")

	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), string(exitErr.Stderr))
		}
		return "", err
	}

	return string(out), nil
}

// executorWithStdin runs a git command with stdin and returns stdout.
func (r *Repository) executorWithStdin(stdin string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = r.gitDirPath
	cmd.Env = append(os.Environ(), "GIT_DIR="+r.gitDirPath, "LC_ALL=C")
	cmd.Stdin = strings.NewReader(stdin)

	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), string(exitErr.Stderr))
		}
		return "", err
	}

	return string(out), nil
}

// resolveGitDir finds the .git directory for a given path.
func resolveGitDir(path string) (string, error) {
	// Check if path itself is a git dir
	if isGitDir(path) {
		return path, nil
	}

	// Check for .git subdirectory
	dotGit := filepath.Join(path, ".git")
	if isGitDir(dotGit) {
		return dotGit, nil
	}

	// Try using git rev-parse
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	cmd.Dir = path
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("could not find git directory in %s", path)
	}

	gitDir := strings.TrimSpace(string(out))
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(path, gitDir)
	}

	return gitDir, nil
}

// isGitDir checks if a path looks like a git directory.
func isGitDir(path string) bool {
	// A git dir has a HEAD file
	_, err := os.Stat(filepath.Join(path, "HEAD"))
	if err != nil {
		return false
	}
	// And either objects/ + refs/ (bare) or is a file (gitdir pointer)
	_, objErr := os.Stat(filepath.Join(path, "objects"))
	_, refErr := os.Stat(filepath.Join(path, "refs"))
	return objErr == nil && refErr == nil
}
