// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package gitinterface

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrRemoteNotFound = errors.New("remote not found")
	ErrPushFailed     = errors.New("push failed")
	ErrFetchFailed    = errors.New("fetch failed")
)

// GetRemotes returns the list of configured remote names.
func (r *Repository) GetRemotes() ([]string, error) {
	output, err := r.executor("remote")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	var remotes []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			remotes = append(remotes, line)
		}
	}

	return remotes, nil
}

// GetRemoteURL returns the URL for a named remote.
func (r *Repository) GetRemoteURL(remoteName string) (string, error) {
	output, err := r.executor("remote", "get-url", remoteName)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrRemoteNotFound, remoteName)
	}
	return strings.TrimSpace(output), nil
}

// FetchRefSpec fetches specific refspecs from a remote.
func (r *Repository) FetchRefSpec(remoteName string, refspecs ...string) error {
	args := []string{"fetch", remoteName}
	args = append(args, refspecs...)

	_, err := r.executor(args...)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFetchFailed, err.Error())
	}

	return nil
}

// PushRefSpec pushes specific refspecs to a remote.
func (r *Repository) PushRefSpec(remoteName string, refspecs ...string) error {
	args := []string{"push", remoteName}
	args = append(args, refspecs...)

	_, err := r.executor(args...)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrPushFailed, err.Error())
	}

	return nil
}

// FetchRef fetches a single ref from a remote.
func (r *Repository) FetchRef(remoteName, refName string) error {
	refspec := fmt.Sprintf("+%s:%s", refName, refName)
	return r.FetchRefSpec(remoteName, refspec)
}

// PushRef pushes a single ref to a remote.
func (r *Repository) PushRef(remoteName, refName string) error {
	return r.PushRefSpec(remoteName, refName)
}

// RefSpec builds a Git refspec string.
// If fastForwardOnly is false, the refspec is prefixed with '+' (force).
func RefSpec(src, dst string, fastForwardOnly bool) string {
	if fastForwardOnly {
		return fmt.Sprintf("%s:%s", src, dst)
	}
	return fmt.Sprintf("+%s:%s", src, dst)
}
