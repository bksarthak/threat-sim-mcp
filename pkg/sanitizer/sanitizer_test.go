package sanitizer

import (
	"strings"
	"testing"
)

func TestSanitizer(t *testing.T) {
	s := New()

	original := "prod-db-us-east-1"
	safe := s.Sanitize(original)

	if !strings.HasPrefix(safe, "NODE_") {
		t.Errorf("Expected safe ID to start with NODE_, got %s", safe)
	}

	restored := s.Restore(safe)
	if restored != original {
		t.Errorf("Expected restored ID to be %s, got %s", original, restored)
	}

	payload := `{"nodes": [{"id": "prod-db-us-east-1"}]}`
	sanitizedPayload := s.SanitizePayload(payload, []string{original})
	
	if strings.Contains(sanitizedPayload, original) {
		t.Errorf("Payload was not sanitized properly: %s", sanitizedPayload)
	}

	restoredPayload := s.RestorePayload(sanitizedPayload)
	if !strings.Contains(restoredPayload, original) {
		t.Errorf("Payload was not restored properly: %s", restoredPayload)
	}
}

func TestRestorePayloadLongestFirstAndSanitizeKnown(t *testing.T) {
	s := New()
	var ids []string
	for i := 0; i < 12; i++ {
		ids = append(ids, s.Sanitize("resource-"+string(rune('a'+i))))
	}
	// Ensure NODE_10 is not corrupted by NODE_1
	payload := ids[1] + " -> " + ids[10]
	restored := s.RestorePayload(payload)
	if restored != "resource-b -> resource-k" {
		t.Errorf("Expected 'resource-b -> resource-k', got %q", restored)
	}

	errMsg := "Source node 'resource-k' not found"
	sanitizedErr := s.SanitizeKnown(errMsg)
	if strings.Contains(sanitizedErr, "resource-k") || !strings.Contains(sanitizedErr, "NODE_10") {
		t.Errorf("SanitizeKnown failed to redact resource-k: %q", sanitizedErr)
	}
}
