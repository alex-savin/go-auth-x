package oidcprovider

import (
	"testing"
	"time"

	authx "github.com/alex-savin/go-auth-x"
)

func TestFreshEnough(t *testing.T) {
	created := time.Date(2026, 1, 1, 12, 0, 0, 500_000_000, time.UTC)
	now := created.Add(10 * time.Second)
	hour, zero := time.Hour, time.Duration(0)
	for _, tc := range []struct {
		name   string
		prompt []string
		maxAge *time.Duration
		authAt time.Time
		want   bool
	}{
		{"no ask", nil, nil, created.Add(-48 * time.Hour), true},
		{"no ask, unknown sign-in", nil, nil, time.Time{}, true},
		{"login, signed in before", []string{"login"}, nil, created.Add(-time.Minute), false},
		{"login, signed in during (same second)", []string{"login"}, nil, created.Truncate(time.Second), true},
		{"login, unknown sign-in", []string{"login"}, nil, time.Time{}, false},
		{"max_age, within", nil, &hour, now.Add(-30 * time.Minute), true},
		{"max_age, past", nil, &hour, now.Add(-2 * time.Hour), false},
		{"max_age 0, before", nil, &zero, created.Add(-time.Second), false},
		{"max_age 0, during", nil, &zero, created.Add(time.Second), true},
		{"max_age, unknown sign-in", nil, &hour, time.Time{}, false},
	} {
		req := &authx.OAuthAuthRequest{Prompt: tc.prompt, MaxAge: tc.maxAge, CreatedAt: created}
		if got := freshEnough(req, tc.authAt, now); got != tc.want {
			t.Errorf("%s: freshEnough = %v, want %v", tc.name, got, tc.want)
		}
	}
}
