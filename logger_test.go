package authx

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
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

// The session's auth_time is the sign-in: stamped when minted fresh, carried over by a re-mint (as
// switching the active org does) while IssuedAt moves on.
func TestSessionAuthTimeSurvivesRemint(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	signIn := time.Now().Add(-time.Hour).Truncate(time.Second)
	tok, err := mintSessionWith(secret, SessionClaims{Email: "e@x.com"}, "local:u", signIn, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := parseSessionMulti([][]byte{secret}, tok)
	if err != nil || sc.AuthTime == nil || !sc.AuthTime.Equal(signIn) {
		t.Fatalf("a fresh session must carry its sign-in time: %v %+v", err, sc)
	}
	base := *sc
	base.Org = "org-1"
	tok2, _ := mintSessionWith(secret, base, sc.Subject, time.Now(), time.Hour)
	sc2, err := parseSessionMulti([][]byte{secret}, tok2)
	if err != nil || !sc2.AuthTime.Equal(signIn) || !sc2.IssuedAt.After(signIn) {
		t.Fatalf("a re-mint must keep auth_time (%v) while iat moves: %+v", signIn, sc2)
	}
}

type stubMailer struct{ err error }

func (m stubMailer) Send(string, string, string, string) error { return m.err }
func (stubMailer) Configured() bool                            { return true }

// Auth emails are logged without the recipient's address: masked, and a success only at Debug.
func TestEmailLogsMaskRecipient(t *testing.T) {
	var buf bytes.Buffer
	a := &Authenticator{cfg: Config{Logger: slog.New(slog.NewTextHandler(&buf, nil))}} // Info and up
	a.email = stubMailer{}
	_ = a.sendAuthEmail("alice@example.com", "Sign in", "h", "i", "c", "https://x", "f")
	if buf.Len() != 0 {
		t.Fatalf("a sent email must not be logged at Info: %q", buf.String())
	}
	a.email = stubMailer{err: errors.New("smtp down")}
	_ = a.sendAuthEmail("alice@example.com", "Sign in", "h", "i", "c", "https://x", "f")
	if out := buf.String(); strings.Contains(out, "alice@") || !strings.Contains(out, "a***@example.com") {
		t.Fatalf("a failed email must log the masked address only: %q", out)
	}
	for in, want := range map[string]string{"bob@x.org": "b***@x.org", "éva@x.org": "é***@x.org", "nope": "***", "@x.org": "***"} {
		if got := maskEmail(in); got != want {
			t.Errorf("maskEmail(%q) = %q, want %q", in, got, want)
		}
	}
}
