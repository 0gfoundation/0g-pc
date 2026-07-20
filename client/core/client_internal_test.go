package core

import "testing"

func TestNewDefaultsProviderURL(t *testing.T) {
	if got := New(Provider{}).provider.URL; got != DefaultProviderURL {
		t.Fatalf("empty URL: got %q, want default %q", got, DefaultProviderURL)
	}
	custom := "https://example.test/v1/chat/completions"
	if got := New(Provider{URL: custom}).provider.URL; got != custom {
		t.Fatalf("explicit URL was overridden: got %q", got)
	}
}
