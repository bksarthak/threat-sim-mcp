package sanitizer

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Sanitizer handles the redaction of sensitive identifiers and maintains
// a bidirectional map to restore them later.
type Sanitizer struct {
	mu            sync.RWMutex
	sensitiveToID map[string]string
	idToSensitive map[string]string
	counter       int
}

// New creates and initializes a new Sanitizer.
func New() *Sanitizer {
	return &Sanitizer{
		sensitiveToID: make(map[string]string),
		idToSensitive: make(map[string]string),
		counter:       0,
	}
}

// Sanitize registers a sensitive string if it hasn't been seen,
// and returns its safe identifier (e.g., "NODE_0").
func (s *Sanitizer) Sanitize(sensitive string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if id, exists := s.sensitiveToID[sensitive]; exists {
		return id
	}

	id := fmt.Sprintf("NODE_%d", s.counter)
	s.counter++

	s.sensitiveToID[sensitive] = id
	s.idToSensitive[id] = sensitive

	return id
}

// Restore converts a safe identifier back to its original sensitive string.
// If the identifier is not found, it returns the input unchanged.
func (s *Sanitizer) Restore(id string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if sensitive, exists := s.idToSensitive[id]; exists {
		return sensitive
	}

	return id
}

// SanitizePayload takes a raw string (e.g., JSON payload) and a list of known
// sensitive identifiers. It replaces all occurrences of the sensitive strings
// with their corresponding safe identifiers and returns the sanitized payload.
// Identifiers are sorted longest-first to prevent substring collision
// (e.g., "aws_vpc.main" corrupting "aws_vpc.main_route_table").
func (s *Sanitizer) SanitizePayload(payload string, identifiers []string) string {
	sorted := make([]string, len(identifiers))
	copy(sorted, identifiers)
	sort.Slice(sorted, func(i, j int) bool {
		return len(sorted[i]) > len(sorted[j])
	})

	sanitizedPayload := payload
	for _, id := range sorted {
		safeNode := s.Sanitize(id)
		sanitizedPayload = strings.ReplaceAll(sanitizedPayload, id, safeNode)
	}
	return sanitizedPayload
}

// SanitizeKnown replaces any already-registered sensitive identifiers in payload
// with their safe NODE_X markers, sorted longest-first to avoid partial matches.
func (s *Sanitizer) SanitizeKnown(payload string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]string, 0, len(s.sensitiveToID))
	for sensitive := range s.sensitiveToID {
		keys = append(keys, sensitive)
	}
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j])
	})

	sanitized := payload
	for _, sensitive := range keys {
		sanitized = strings.ReplaceAll(sanitized, sensitive, s.sensitiveToID[sensitive])
	}
	return sanitized
}

// RestorePayload takes a sanitized payload and replaces all safe identifiers
// back with their original sensitive strings (sorted longest-first so NODE_1
// does not corrupt NODE_10).
func (s *Sanitizer) RestorePayload(payload string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	safeIDs := make([]string, 0, len(s.idToSensitive))
	for safeID := range s.idToSensitive {
		safeIDs = append(safeIDs, safeID)
	}
	sort.Slice(safeIDs, func(i, j int) bool {
		return len(safeIDs[i]) > len(safeIDs[j])
	})

	restoredPayload := payload
	for _, safeID := range safeIDs {
		restoredPayload = strings.ReplaceAll(restoredPayload, safeID, s.idToSensitive[safeID])
	}
	return restoredPayload
}
