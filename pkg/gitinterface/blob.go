// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package gitinterface

import (
	"fmt"
	"strings"
)

// ReadBlob reads the contents of a blob object.
func (r *Repository) ReadBlob(blobID Hash) ([]byte, error) {
	output, err := r.executor("cat-file", "-p", blobID.String())
	if err != nil {
		return nil, fmt.Errorf("reading blob %s: %w", blobID.String(), err)
	}
	return []byte(output), nil
}

// WriteBlob writes content as a blob object and returns its hash.
func (r *Repository) WriteBlob(contents []byte) (Hash, error) {
	output, err := r.executorWithStdin(string(contents), "hash-object", "-w", "--stdin")
	if err != nil {
		return ZeroHash, fmt.Errorf("writing blob: %w", err)
	}
	return NewHash(strings.TrimSpace(output))
}
