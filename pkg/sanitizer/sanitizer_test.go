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
