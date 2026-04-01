// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package gitinterface

import (
	"errors"
	"fmt"
	"strings"
)

// ObjectType represents the type of a Git object.
type ObjectType string

const (
	BlobObjectType   ObjectType = "blob"
	TreeObjectType   ObjectType = "tree"
	CommitObjectType ObjectType = "commit"
	TagObjectType    ObjectType = "tag"
)

var ErrInvalidObjectType = errors.New("invalid object type")

// HasObject returns true if the object exists in the repository.
func (r *Repository) HasObject(objectID Hash) bool {
	_, err := r.executor("cat-file", "-t", objectID.String())
	return err == nil
}

// GetObjectType returns the type of a Git object.
func (r *Repository) GetObjectType(objectID Hash) (ObjectType, error) {
	output, err := r.executor("cat-file", "-t", objectID.String())
	if err != nil {
		return "", fmt.Errorf("getting object type: %w", err)
	}

	t := ObjectType(strings.TrimSpace(output))
	switch t {
	case BlobObjectType, TreeObjectType, CommitObjectType, TagObjectType:
		return t, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrInvalidObjectType, t)
	}
}
