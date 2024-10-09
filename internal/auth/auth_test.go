package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("No Authorization header", func(t *testing.T) {
		headers := http.Header{}
		_, err := GetAPIKey(headers)
		if err != ErrNoAuthHeaderIncluded {
			t.Errorf("expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
		}
	})

	t.Run("Malformed Authorization header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer some_token")
		_, err := GetAPIKey(headers)
		expectedErr := "malformed authorization header"
		if err == nil || err.Error() != expectedErr {
			t.Errorf("expected error %v, got %v", expectedErr, err)
		}
	})

	t.Run("Valid ApiKey header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey valid_api_key")
		apiKey, err := GetAPIKey(headers)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		expectedAPIKey := "valid_api_key"
		if apiKey != expectedAPIKey {
			t.Errorf("expected API key %v, got %v", expectedAPIKey, apiKey)
		}
	})
}
