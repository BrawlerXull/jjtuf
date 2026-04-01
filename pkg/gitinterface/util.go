// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package gitinterface

import (
	"os"
)

// writeTempFile writes data to a temporary file and returns its path.
func writeTempFile(data []byte) (string, error) {
	f, err := os.CreateTemp("", "jjtuf-key-*")
	if err != nil {
		return "", err
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}

	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}

	// SSH keys need restrictive permissions
	if err := os.Chmod(f.Name(), 0600); err != nil {
		os.Remove(f.Name())
		return "", err
	}

	return f.Name(), nil
}

// removeFile removes a file, ignoring errors.
func removeFile(path string) {
	os.Remove(path) //nolint:errcheck
}
