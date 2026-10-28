package authx

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// TestLogger_ZeroValueFallsBackToDefault pins that the logger seam is nil-safe: the zero value is a
// valid Authenticator by design, so its warning paths must fall back to slog.Default(), not panic.
func TestLogger_ZeroValueFallsBackToDefault(t *testing.T) {
	a := &Authenticator{}   // no Config.Logger, no SESSION_SECRET
	a.SetLocalEnabled(true) // warns about the absent secret
	_ = a.Close()
}

func TestLogger_ConfigAndSetLogger(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "") // unset → New warns
	var boot bytes.Buffer
	a, err := New(context.Background(), Config{Logger: slog.New(slog.NewTextHandler(&boot, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(boot.String(), "level=WARN") || !strings.Contains(boot.String(), "TRUSTED_PROXIES") {
		t.Fatalf("Config.Logger must receive New's boot warnings, got %q", boot.String())
	}

	var later bytes.Buffer
	a.SetLogger(slog.New(slog.NewTextHandler(&later, nil)))
	a.SetLocalEnabled(true) // no SESSION_SECRET → warns through the swapped logger
	defer a.Close()
	if !strings.Contains(later.String(), "SESSION_SECRET is too short") || !strings.Contains(later.String(), "min_bytes=32") {
		t.Fatalf("SetLogger must route later warnings, got %q", later.String())
	}
	if strings.Contains(boot.String(), "SESSION_SECRET is too short") {
		t.Fatal("a replaced logger must not keep receiving records")
	}
}
