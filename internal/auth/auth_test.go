package auth

import "testing"

func TestGetAPIKey_NoAuthHeader(t *testing.T) {
	headers := make(map[string][]string)
	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Fatalf("expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
	}
}

func TestGetAPIKey_MalformedAuthHeader(t *testing.T) {
	headers := make(map[string][]string)
	headers["Authorization"] = []string{"Bearer some_token"}
	_, err := GetAPIKey(headers)
	if err == nil || err.Error() != "malformed authorization header" {
		t.Fatalf("expected malformed authorization header error, got %v", err)
	}
}

func TestGetAPIKey_ValidAuthHeader(t *testing.T) {
	headers := make(map[string][]string)
	expectedAPIKey := "my_secret_api_key"
	headers["Authorization"] = []string{"ApiKey " + expectedAPIKey}
	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if apiKey != expectedAPIKey {
		t.Fatalf("expected API key %s, got %s", expectedAPIKey, apiKey)
	}
}
