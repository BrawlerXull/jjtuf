// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

// Package osl implements the Operation State Log (OSL) for jjtuf.
// The OSL is an append-only, cryptographically signed log of jj operations
// stored as a chain of Git commits in refs/jjtuf/operation-state-log.
// It is the jj-adapted equivalent of gittuf's Reference State Log (RSL).
package osl

import (
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jjtuf/jjtuf/pkg/gitinterface"
)

const (
	// Ref is the Git reference where the OSL is stored.
	Ref = "refs/jjtuf/operation-state-log"

	// NumberKey is the key for the entry sequence number.
	NumberKey = "number"

	// OperationEntryHeader identifies an operation entry in the OSL.
	OperationEntryHeader = "OSL Operation Entry"

	// OperationIDKey is the key for the jj operation ID.
	OperationIDKey = "operationID"

	// ParentOperationIDsKey is the key for parent operation IDs.
	ParentOperationIDsKey = "parentOperationIDs"

	// ViewDigestKey is the key for the SHA-256 digest of the operation's View.
	ViewDigestKey = "viewDigest"

	// BookmarkDeltaKey is the key for bookmark change records.
	BookmarkDeltaKey = "bookmarkDelta"

	// AnnotationEntryHeader identifies an annotation entry.
	AnnotationEntryHeader = "OSL Annotation Entry"

	// AnnotationMessageBlockType is the PEM block type for annotation messages.
	AnnotationMessageBlockType = "MESSAGE"
	BeginMessage               = "-----BEGIN MESSAGE-----"
	EndMessage                 = "-----END MESSAGE-----"

	// EntryIDKey is the key for referencing other OSL entries.
	EntryIDKey = "entryID"

	// SkipKey indicates whether referenced entries should be skipped.
	SkipKey = "skip"

	// PropagationEntryHeader identifies a propagation entry.
	PropagationEntryHeader = "OSL Propagation Entry"
	UpstreamRepositoryKey  = "upstreamRepository"
	UpstreamEntryIDKey     = "upstreamEntryID"

	remoteTrackerRef      = "refs/remotes/%s/jjtuf/operation-state-log"
	jjtufNamespacePrefix  = "refs/jjtuf/"
	jjtufPolicyStagingRef = "refs/jjtuf/policy-staging"
)

var (
	ErrOSLEntryNotFound   = errors.New("unable to find OSL entry")
	ErrOSLBranchDetected  = errors.New("potential OSL branch detected, entry has more than one parent")
	ErrInvalidOSLEntry    = errors.New("OSL entry has invalid format or is of unexpected type")
	ErrNoRecordOfCommit   = errors.New("commit has not been encountered before")
)

// RemoteTrackerRef returns the remote tracking ref for the specified remote.
func RemoteTrackerRef(remote string) string {
	return fmt.Sprintf(remoteTrackerRef, remote)
}

// Entry is the abstract representation of an object in the OSL.
type Entry interface {
	GetID() gitinterface.Hash
	Commit(repo *gitinterface.Repository, sign bool) error
	GetNumber() uint64
	createCommitMessage(includeNumber bool) (string, error)
}

// BookmarkDelta records a change to a bookmark in a jj operation.
type BookmarkDelta struct {
	// Name is the bookmark name (e.g., "main", "feature/auth").
	Name string

	// FromID is the previous commit ID ("" if bookmark is new).
	FromID string

	// ToID is the new commit ID ("" if bookmark is deleted).
	ToID string

	// Conflict indicates whether the bookmark is in a conflicted state.
	Conflict bool
}

// OperationEntry records a jj operation in the OSL.
// It is the jj-adapted equivalent of gittuf's ReferenceEntry.
type OperationEntry struct {
	// ID is the Git commit hash of this OSL entry.
	ID gitinterface.Hash

	// OperationID is the jj operation ID (BLAKE2b-512 hex).
	OperationID string

	// ParentOpIDs are the jj parent operation IDs.
	ParentOpIDs []string

	// ViewDigest is the SHA-256 hash of the canonical View serialization.
	ViewDigest string

	// BookmarkDeltas records what bookmarks changed in this operation.
	BookmarkDeltas []BookmarkDelta

	// Number is a strictly increasing sequence number.
	Number uint64
}

// NewOperationEntry creates a new OperationEntry.
func NewOperationEntry(operationID string, parentOpIDs []string, viewDigest string, deltas []BookmarkDelta) *OperationEntry {
	return &OperationEntry{
		OperationID:    operationID,
		ParentOpIDs:    parentOpIDs,
		ViewDigest:     viewDigest,
		BookmarkDeltas: deltas,
	}
}

func (e *OperationEntry) GetID() gitinterface.Hash { return e.ID }
func (e *OperationEntry) GetNumber() uint64         { return e.Number }

// Commit creates a signed Git commit for this entry on the OSL ref.
func (e *OperationEntry) Commit(repo *gitinterface.Repository, sign bool) error {
	if err := e.setEntryNumber(repo); err != nil {
		return err
	}

	message, _ := e.createCommitMessage(true)

	emptyTreeID, err := repo.EmptyTree()
	if err != nil {
		return err
	}

	_, err = repo.Commit(emptyTreeID, Ref, message, sign)
	return err
}

// CommitUsingSpecificKey creates a commit signed with a specific key.
func (e *OperationEntry) CommitUsingSpecificKey(repo *gitinterface.Repository, signingKeyBytes []byte) error {
	if err := e.setEntryNumber(repo); err != nil {
		return err
	}

	message, _ := e.createCommitMessage(true)

	emptyTreeID, err := repo.EmptyTree()
	if err != nil {
		return err
	}

	_, err = repo.CommitUsingSpecificKey(emptyTreeID, Ref, message, signingKeyBytes)
	return err
}

func (e *OperationEntry) setEntryNumber(repo *gitinterface.Repository) error {
	latestEntry, err := GetLatestEntry(repo)
	if err == nil {
		e.Number = latestEntry.GetNumber() + 1
	} else {
		if errors.Is(err, ErrOSLEntryNotFound) {
			e.Number = 1
		} else {
			return err
		}
	}
	return nil
}

func (e *OperationEntry) createCommitMessage(includeNumber bool) (string, error) {
	lines := []string{
		OperationEntryHeader,
		"",
		fmt.Sprintf("%s: %s", OperationIDKey, e.OperationID),
		fmt.Sprintf("%s: %s", ParentOperationIDsKey, strings.Join(e.ParentOpIDs, ",")),
		fmt.Sprintf("%s: %s", ViewDigestKey, e.ViewDigest),
	}

	for _, delta := range e.BookmarkDeltas {
		value := fmt.Sprintf("%s:%s:%s", delta.Name, delta.FromID, delta.ToID)
		if delta.Conflict {
			value += ":conflict"
		}
		lines = append(lines, fmt.Sprintf("%s: %s", BookmarkDeltaKey, value))
	}

	if includeNumber && e.Number > 0 {
		lines = append(lines, fmt.Sprintf("%s: %d", NumberKey, e.Number))
	}

	return strings.Join(lines, "\n"), nil
}

// AnnotationEntry marks prior OSL entries as skipped or adds context.
type AnnotationEntry struct {
	// ID is the Git commit hash of this annotation.
	ID gitinterface.Hash

	// OSLEntryIDs contains hashes of the OSL entries this annotation applies to.
	OSLEntryIDs []gitinterface.Hash

	// Skip indicates if the referenced entries must be skipped.
	Skip bool

	// Message contains optional notes added by a user.
	Message string

	// Number is a strictly increasing sequence number.
	Number uint64
}

// NewAnnotationEntry creates a new AnnotationEntry.
func NewAnnotationEntry(oslEntryIDs []gitinterface.Hash, skip bool, message string) *AnnotationEntry {
	return &AnnotationEntry{OSLEntryIDs: oslEntryIDs, Skip: skip, Message: message}
}

func (a *AnnotationEntry) GetID() gitinterface.Hash { return a.ID }
func (a *AnnotationEntry) GetNumber() uint64         { return a.Number }

// RefersTo returns true if this annotation references the given entry ID.
func (a *AnnotationEntry) RefersTo(entryID gitinterface.Hash) bool {
	for _, id := range a.OSLEntryIDs {
		if id.Equal(entryID) {
			return true
		}
	}
	return false
}

// Commit creates a signed Git commit for this annotation on the OSL ref.
func (a *AnnotationEntry) Commit(repo *gitinterface.Repository, sign bool) error {
	// Verify referenced entries exist
	for _, id := range a.OSLEntryIDs {
		if _, err := GetEntry(repo, id); err != nil {
			return err
		}
	}

	if err := a.setEntryNumber(repo); err != nil {
		return err
	}

	message, err := a.createCommitMessage(true)
	if err != nil {
		return err
	}

	emptyTreeID, err := repo.EmptyTree()
	if err != nil {
		return err
	}

	_, err = repo.Commit(emptyTreeID, Ref, message, sign)
	return err
}

func (a *AnnotationEntry) setEntryNumber(repo *gitinterface.Repository) error {
	latestEntry, err := GetLatestEntry(repo)
	if err == nil {
		a.Number = latestEntry.GetNumber() + 1
	} else {
		if errors.Is(err, ErrOSLEntryNotFound) {
			a.Number = 1
		} else {
			return err
		}
	}
	return nil
}

func (a *AnnotationEntry) createCommitMessage(includeNumber bool) (string, error) {
	lines := []string{
		AnnotationEntryHeader,
		"",
	}

	for _, id := range a.OSLEntryIDs {
		lines = append(lines, fmt.Sprintf("%s: %s", EntryIDKey, id.String()))
	}

	lines = append(lines, fmt.Sprintf("%s: %t", SkipKey, a.Skip))

	if includeNumber && a.Number > 0 {
		lines = append(lines, fmt.Sprintf("%s: %d", NumberKey, a.Number))
	}

	if a.Message != "" {
		block := pem.EncodeToMemory(&pem.Block{
			Type:  AnnotationMessageBlockType,
			Bytes: []byte(a.Message),
		})
		lines = append(lines, string(block))
	}

	return strings.Join(lines, "\n"), nil
}

// PropagationEntry tracks upstream repository synchronization.
type PropagationEntry struct {
	ID                 gitinterface.Hash
	UpstreamRepository string
	UpstreamEntryID    gitinterface.Hash
	Number             uint64
}

func (p *PropagationEntry) GetID() gitinterface.Hash { return p.ID }
func (p *PropagationEntry) GetNumber() uint64         { return p.Number }

func (p *PropagationEntry) Commit(repo *gitinterface.Repository, sign bool) error {
	if err := p.setEntryNumber(repo); err != nil {
		return err
	}

	message, _ := p.createCommitMessage(true)

	emptyTreeID, err := repo.EmptyTree()
	if err != nil {
		return err
	}

	_, err = repo.Commit(emptyTreeID, Ref, message, sign)
	return err
}

func (p *PropagationEntry) setEntryNumber(repo *gitinterface.Repository) error {
	latestEntry, err := GetLatestEntry(repo)
	if err == nil {
		p.Number = latestEntry.GetNumber() + 1
	} else {
		if errors.Is(err, ErrOSLEntryNotFound) {
			p.Number = 1
		} else {
			return err
		}
	}
	return nil
}

func (p *PropagationEntry) createCommitMessage(includeNumber bool) (string, error) {
	lines := []string{
		PropagationEntryHeader,
		"",
		fmt.Sprintf("%s: %s", UpstreamRepositoryKey, p.UpstreamRepository),
		fmt.Sprintf("%s: %s", UpstreamEntryIDKey, p.UpstreamEntryID.String()),
	}

	if includeNumber && p.Number > 0 {
		lines = append(lines, fmt.Sprintf("%s: %d", NumberKey, p.Number))
	}

	return strings.Join(lines, "\n"), nil
}

// IsOperationIDRecorded returns true if the given jj operation ID is already
// present in the OSL. Used to prevent duplicate entries when osl record is
// called more than once without intervening jj operations.
func IsOperationIDRecorded(repo *gitinterface.Repository, operationID string) (bool, error) {
	found := false
	err := IterateEntries(repo, func(entry Entry) bool {
		opEntry, ok := entry.(*OperationEntry)
		if !ok {
			return true
		}
		if opEntry.OperationID == operationID {
			found = true
			return false
		}
		return true
	})
	if err != nil && !errors.Is(err, ErrOSLEntryNotFound) {
		return false, err
	}
	return found, nil
}

// GetLatestEntry returns the most recent entry in the OSL.
func GetLatestEntry(repo *gitinterface.Repository) (Entry, error) {
	tipID, err := repo.GetReference(Ref)
	if err != nil {
		return nil, ErrOSLEntryNotFound
	}
	return GetEntry(repo, tipID)
}

// GetEntry parses an OSL entry from its Git commit.
func GetEntry(repo *gitinterface.Repository, entryID gitinterface.Hash) (Entry, error) {
	message, err := repo.GetCommitMessage(entryID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrOSLEntryNotFound, err.Error())
	}

	return parseEntry(entryID, message)
}

// parseEntry parses a commit message into the appropriate Entry type.
func parseEntry(entryID gitinterface.Hash, message string) (Entry, error) {
	lines := strings.Split(message, "\n")
	if len(lines) == 0 {
		return nil, ErrInvalidOSLEntry
	}

	header := strings.TrimSpace(lines[0])
	switch header {
	case OperationEntryHeader:
		return parseOperationEntry(entryID, lines)
	case AnnotationEntryHeader:
		return parseAnnotationEntry(entryID, lines)
	case PropagationEntryHeader:
		return parsePropagationEntry(entryID, lines)
	default:
		return nil, fmt.Errorf("%w: unknown header %q", ErrInvalidOSLEntry, header)
	}
}

func parseOperationEntry(entryID gitinterface.Hash, lines []string) (*OperationEntry, error) {
	entry := &OperationEntry{ID: entryID}

	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		key, value, ok := parseKeyValue(line)
		if !ok {
			continue
		}

		switch key {
		case OperationIDKey:
			entry.OperationID = value
		case ParentOperationIDsKey:
			if value != "" {
				entry.ParentOpIDs = strings.Split(value, ",")
			}
		case ViewDigestKey:
			entry.ViewDigest = value
		case BookmarkDeltaKey:
			delta, err := parseBookmarkDelta(value)
			if err != nil {
				return nil, err
			}
			entry.BookmarkDeltas = append(entry.BookmarkDeltas, delta)
		case NumberKey:
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid number %q", ErrInvalidOSLEntry, value)
			}
			entry.Number = n
		}
	}

	return entry, nil
}

func parseAnnotationEntry(entryID gitinterface.Hash, lines []string) (*AnnotationEntry, error) {
	entry := &AnnotationEntry{ID: entryID}

	// Check for PEM-encoded message
	fullMessage := strings.Join(lines, "\n")
	if strings.Contains(fullMessage, BeginMessage) {
		block, _ := pem.Decode([]byte(fullMessage[strings.Index(fullMessage, BeginMessage):]))
		if block != nil {
			entry.Message = string(block.Bytes)
		}
	}

	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}

		key, value, ok := parseKeyValue(line)
		if !ok {
			continue
		}

		switch key {
		case EntryIDKey:
			h, err := gitinterface.NewHash(value)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid entry ID %q", ErrInvalidOSLEntry, value)
			}
			entry.OSLEntryIDs = append(entry.OSLEntryIDs, h)
		case SkipKey:
			entry.Skip = value == "true"
		case NumberKey:
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid number %q", ErrInvalidOSLEntry, value)
			}
			entry.Number = n
		}
	}

	return entry, nil
}

func parsePropagationEntry(entryID gitinterface.Hash, lines []string) (*PropagationEntry, error) {
	entry := &PropagationEntry{ID: entryID}

	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		key, value, ok := parseKeyValue(line)
		if !ok {
			continue
		}

		switch key {
		case UpstreamRepositoryKey:
			entry.UpstreamRepository = value
		case UpstreamEntryIDKey:
			h, err := gitinterface.NewHash(value)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid upstream entry ID", ErrInvalidOSLEntry)
			}
			entry.UpstreamEntryID = h
		case NumberKey:
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid number", ErrInvalidOSLEntry)
			}
			entry.Number = n
		}
	}

	return entry, nil
}

func parseBookmarkDelta(value string) (BookmarkDelta, error) {
	parts := strings.Split(value, ":")
	if len(parts) < 3 {
		return BookmarkDelta{}, fmt.Errorf("%w: invalid bookmark delta %q", ErrInvalidOSLEntry, value)
	}

	delta := BookmarkDelta{
		Name:   parts[0],
		FromID: parts[1],
		ToID:   parts[2],
	}

	if len(parts) >= 4 && parts[3] == "conflict" {
		delta.Conflict = true
	}

	return delta, nil
}

func parseKeyValue(line string) (string, string, bool) {
	idx := strings.Index(line, ": ")
	if idx < 0 {
		return "", "", false
	}
	return line[:idx], line[idx+2:], true
}

// GetLatestOperationEntry returns the latest OperationEntry, walking past annotations.
func GetLatestOperationEntry(repo *gitinterface.Repository) (*OperationEntry, error) {
	tipID, err := repo.GetReference(Ref)
	if err != nil {
		return nil, ErrOSLEntryNotFound
	}

	currentID := tipID
	for {
		entry, err := GetEntry(repo, currentID)
		if err != nil {
			return nil, err
		}

		if opEntry, ok := entry.(*OperationEntry); ok {
			return opEntry, nil
		}

		// Walk to parent
		parents, err := repo.GetCommitParentIDs(currentID)
		if err != nil || len(parents) == 0 {
			return nil, ErrOSLEntryNotFound
		}
		currentID = parents[0]
	}
}

// IterateEntries walks the OSL from the tip backwards, calling fn for each entry.
// If fn returns false, iteration stops.
func IterateEntries(repo *gitinterface.Repository, fn func(Entry) bool) error {
	tipID, err := repo.GetReference(Ref)
	if err != nil {
		return ErrOSLEntryNotFound
	}

	currentID := tipID
	for {
		entry, err := GetEntry(repo, currentID)
		if err != nil {
			return err
		}

		if !fn(entry) {
			return nil
		}

		parents, err := repo.GetCommitParentIDs(currentID)
		if err != nil || len(parents) == 0 {
			return nil // Reached root
		}

		if len(parents) > 1 {
			return ErrOSLBranchDetected
		}

		currentID = parents[0]
	}
}
