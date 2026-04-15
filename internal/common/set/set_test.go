// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package set

import (
	"testing"
)

func TestNewSet(t *testing.T) {
	s := New[string]()
	if s.Len() != 0 {
		t.Errorf("expected empty set, got %d", s.Len())
	}
}

func TestNewFromItems(t *testing.T) {
	s := NewFromItems("a", "b", "c")
	if s.Len() != 3 {
		t.Errorf("expected 3 items, got %d", s.Len())
	}
	if !s.Has("a") || !s.Has("b") || !s.Has("c") {
		t.Error("missing expected items")
	}
}

func TestAddAndHas(t *testing.T) {
	s := New[int]()
	s.Add(42)
	if !s.Has(42) {
		t.Error("expected 42 to be in set")
	}
	if s.Has(99) {
		t.Error("expected 99 to not be in set")
	}
}

func TestRemove(t *testing.T) {
	s := NewFromItems("x", "y")
	s.Remove("x")
	if s.Has("x") {
		t.Error("expected x to be removed")
	}
	if !s.Has("y") {
		t.Error("expected y to remain")
	}
}

func TestDuplicateAdd(t *testing.T) {
	s := New[string]()
	s.Add("dup")
	s.Add("dup")
	if s.Len() != 1 {
		t.Errorf("expected 1, got %d", s.Len())
	}
}

func TestIntersection(t *testing.T) {
	a := NewFromItems("x", "y", "z")
	b := NewFromItems("y", "z", "w")
	c := a.Intersection(b)
	if c.Len() != 2 {
		t.Errorf("expected intersection size 2, got %d", c.Len())
	}
	if !c.Has("y") || !c.Has("z") {
		t.Error("intersection missing expected items")
	}
	if c.Has("x") || c.Has("w") {
		t.Error("intersection has unexpected items")
	}
}

func TestContents(t *testing.T) {
	s := NewFromItems(1, 2, 3)
	contents := s.Contents()
	if len(contents) != 3 {
		t.Errorf("expected 3 contents, got %d", len(contents))
	}
}
