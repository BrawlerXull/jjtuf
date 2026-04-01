// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package set

// Set is a generic set data structure.
type Set[T comparable] struct {
	contents map[T]bool
}

// New creates an empty Set.
func New[T comparable]() *Set[T] {
	return &Set[T]{contents: map[T]bool{}}
}

// NewFromItems creates a Set pre-populated with the given items.
func NewFromItems[T comparable](items ...T) *Set[T] {
	s := New[T]()
	for _, item := range items {
		s.Add(item)
	}
	return s
}

// Add inserts an item into the set.
func (s *Set[T]) Add(item T) {
	s.contents[item] = true
}

// Remove deletes an item from the set.
func (s *Set[T]) Remove(item T) {
	delete(s.contents, item)
}

// Has returns true if the item exists in the set.
func (s *Set[T]) Has(item T) bool {
	return s.contents[item]
}

// Len returns the number of items in the set.
func (s *Set[T]) Len() int {
	return len(s.contents)
}

// Contents returns all items in the set as a slice.
func (s *Set[T]) Contents() []T {
	items := make([]T, 0, len(s.contents))
	for item := range s.contents {
		items = append(items, item)
	}
	return items
}

// Intersection returns a new Set containing items present in both sets.
func (s *Set[T]) Intersection(other *Set[T]) *Set[T] {
	result := New[T]()
	for item := range s.contents {
		if other.Has(item) {
			result.Add(item)
		}
	}
	return result
}
