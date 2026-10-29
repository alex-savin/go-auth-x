package gormstore

import (
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	authx "github.com/alex-savin/go-auth-x"
)

func TestOAuthStore(t *testing.T) {
	testOAuthStore(t, func(t *testing.T) authx.OAuthStore {
		// busy_timeout: the atomic-use test has 20 goroutines writing one SQLite file at once.
		dsn := filepath.Join(t.TempDir(), "authx.db") + "?_pragma=busy_timeout(5000)"
		db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
		if err != nil {
			t.Fatal(err)
		}
		s, err := New(db)
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

// testOAuthStore is the behavioural contract of authx.OAuthStore (kept identical in memory and
// gormstore). newStore must return an empty store.
func testOAuthStore(t *testing.T, newStore func(t *testing.T) authx.OAuthStore) {
	// Microsecond precision: what Postgres keeps; the stores must round-trip at least that.
	base := time.Now().Truncate(time.Microsecond)
	at := func(d time.Duration) time.Time { return base.Add(d) }
	tp := func(d time.Duration) *time.Time { v := at(d); return &v }
	eqTime := func(t *testing.T, name string, got, want time.Time) {
		t.Helper()
		if !got.Equal(want) {
			t.Errorf("%s: got %v, want %v", name, got, want)
		}
	}
	eqTimePtr := func(t *testing.T, name string, got, want *time.Time) {
		t.Helper()
		if (got == nil) != (want == nil) || (got != nil && !got.Equal(*want)) {
			t.Errorf("%s: got %v, want %v", name, got, want)
		}
	}
	// eqList also tells nil from empty.
	eqList := func(t *testing.T, name string, got, want []string) {
		t.Helper()
		if (got == nil) != (want == nil) || !reflect.DeepEqual(append([]string{}, got...), append([]string{}, want...)) {
			t.Errorf("%s: got %#v, want %#v", name, got, want)
		}
	}

	t.Run("clients", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.OAuthClient("nope"); !errors.Is(err, authx.ErrOAuthNotFound) {
			t.Fatalf("absent client: want ErrOAuthNotFound, got %v", err)
		}
		in := &authx.OAuthClient{
			ID: "c1", SecretHash: "ab12", Name: "App", URI: "https://app", LogoURI: "https://app/logo",
			RedirectURIs: []string{"https://app/cb", "http://127.0.0.1/cb"}, GrantTypes: []string{},
			AuthMethod: "client_secret_basic", Dynamic: true, CreatedAt: at(0),
		}
		if err := s.CreateOAuthClient(in); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateOAuthClient(&authx.OAuthClient{ID: "c1"}); err == nil {
			t.Fatal("a duplicate client ID must fail")
		}
		in.RedirectURIs[0] = "mutated" // the store must have kept its own copy
		got, err := s.OAuthClient("c1")
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != "c1" || got.SecretHash != "ab12" || got.Name != "App" || got.URI != "https://app" ||
			got.LogoURI != "https://app/logo" || got.AuthMethod != "client_secret_basic" || !got.Dynamic {
			t.Fatalf("client fields: %+v", got)
		}
		eqList(t, "RedirectURIs", got.RedirectURIs, []string{"https://app/cb", "http://127.0.0.1/cb"})
		eqList(t, "GrantTypes (empty)", got.GrantTypes, []string{})
		eqTime(t, "CreatedAt", got.CreatedAt, at(0))
		if !got.LastUsedAt.IsZero() {
			t.Fatalf("LastUsedAt: want zero, got %v", got.LastUsedAt)
		}
		got.RedirectURIs[0] = "mutated" // nor alias what it hands out
		if again, _ := s.OAuthClient("c1"); again.RedirectURIs[0] != "https://app/cb" {
			t.Fatal("returned slices must not alias the stored record")
		}

		if err := s.TouchOAuthClient("c1", at(time.Hour)); err != nil {
			t.Fatal(err)
		}
		got, _ = s.OAuthClient("c1")
		eqTime(t, "LastUsedAt", got.LastUsedAt, at(time.Hour))
		if err := s.TouchOAuthClient("nope", at(0)); !errors.Is(err, authx.ErrOAuthNotFound) {
			t.Fatalf("touch absent: want ErrOAuthNotFound, got %v", err)
		}

		// A nil list round-trips as nil.
		if err := s.CreateOAuthClient(&authx.OAuthClient{ID: "c2", AuthMethod: "none", CreatedAt: at(0)}); err != nil {
			t.Fatal(err)
		}
		c2, _ := s.OAuthClient("c2")
		eqList(t, "RedirectURIs (nil)", c2.RedirectURIs, nil)
		eqList(t, "GrantTypes (nil)", c2.GrantTypes, nil)

		if err := s.DeleteOAuthClient("c1"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.OAuthClient("c1"); !errors.Is(err, authx.ErrOAuthNotFound) {
			t.Fatalf("deleted client: want ErrOAuthNotFound, got %v", err)
		}
		if err := s.DeleteOAuthClient("c1"); err != nil {
			t.Fatalf("deleting an absent client is a no-op, got %v", err)
		}
	})

	t.Run("client delete cascades", func(t *testing.T) {
		s := newStore(t)
		_ = s.CreateOAuthClient(&authx.OAuthClient{ID: "c", CreatedAt: at(0)})
		_ = s.SaveOAuthAuthRequest(&authx.OAuthAuthRequest{ID: "r", ClientID: "c", CreatedAt: at(0)})
		_ = s.CreateOAuthGrant(&authx.OAuthGrant{ID: "g", ClientID: "c", CreatedAt: at(0)})
		_ = s.CreateOAuthAccessToken(&authx.OAuthAccessToken{ID: "a", GrantID: "g", ClientID: "c", ExpiresAt: at(time.Hour)})
		_ = s.CreateOAuthRefreshToken(&authx.OAuthRefreshToken{Hash: "h", GrantID: "g", ClientID: "c", ExpiresAt: at(time.Hour)})
		if err := s.DeleteOAuthClient("c"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.OAuthAuthRequest("r"); !errors.Is(err, authx.ErrOAuthNotFound) {
			t.Error("auth request of a deleted client must go")
		}
		if _, err := s.OAuthGrant("g"); !errors.Is(err, authx.ErrOAuthNotFound) {
			t.Error("grant of a deleted client must go")
		}
		if _, err := s.OAuthAccessToken("a"); !errors.Is(err, authx.ErrOAuthNotFound) {
			t.Error("access token of a deleted client must go")
		}
		if _, err := s.OAuthRefreshToken("h"); !errors.Is(err, authx.ErrOAuthNotFound) {
			t.Error("refresh token of a deleted client must go")
		}
	})

	t.Run("auth requests", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.OAuthAuthRequest("nope"); !errors.Is(err, authx.ErrOAuthNotFound) {
			t.Fatalf("absent request: want ErrOAuthNotFound, got %v", err)
		}
		r := &authx.OAuthAuthRequest{
			ID: "r1", ClientID: "c1", RedirectURI: "https://app/cb", State: "st", Nonce: "n",
			Scopes: []string{"openid", "profile"}, ResponseType: "code", ResponseMode: "query",
			CodeChallenge: "chal", CodeChallengeMethod: "S256",
			Resources: []string{}, Prompt: nil, CreatedAt: at(0),
		}
		if err := s.SaveOAuthAuthRequest(r); err != nil {
			t.Fatal(err)
		}
		got, err := s.OAuthAuthRequest("r1")
		if err != nil {
			t.Fatal(err)
		}
		if got.ClientID != "c1" || got.RedirectURI != "https://app/cb" || got.State != "st" || got.Nonce != "n" ||
			got.ResponseType != "code" || got.ResponseMode != "query" || got.CodeChallenge != "chal" ||
			got.CodeChallengeMethod != "S256" || got.Done || got.Subject != "" || got.CodeHash != "" {
			t.Fatalf("request fields: %+v", got)
		}
		eqList(t, "Scopes", got.Scopes, []string{"openid", "profile"})
		eqList(t, "Resources (empty)", got.Resources, []string{})
		eqList(t, "Prompt (nil)", got.Prompt, nil)
		eqTime(t, "CreatedAt", got.CreatedAt, at(0))
		if !got.AuthTime.IsZero() || !got.CodeAt.IsZero() || !got.GrantExpiresAt.IsZero() {
			t.Fatalf("unset times must stay zero: %+v", got)
		}
		if _, err := s.OAuthAuthRequestByCode(""); !errors.Is(err, authx.ErrOAuthNotFound) {
			t.Fatal("an empty code hash must never match a request without a code")
		}

		// Save again: replaces (approval + code issued).
		r.Subject, r.Ref, r.Done = "user-1", "conn-9", true
		r.GrantExpiresAt, r.AuthTime = at(30*24*time.Hour), at(time.Minute)
		r.CodeHash, r.CodeAt = "codehash", at(2*time.Minute)
		r.Prompt = []string{"consent"}
		if err := s.SaveOAuthAuthRequest(r); err != nil {
			t.Fatal(err)
		}
		got, err = s.OAuthAuthRequestByCode("codehash")
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != "r1" || got.Subject != "user-1" || got.Ref != "conn-9" || !got.Done || got.CodeHash != "codehash" {
			t.Fatalf("upserted request: %+v", got)
		}
		eqTime(t, "GrantExpiresAt", got.GrantExpiresAt, at(30*24*time.Hour))
		eqTime(t, "AuthTime", got.AuthTime, at(time.Minute))
		eqTime(t, "CodeAt", got.CodeAt, at(2*time.Minute))
		eqList(t, "Prompt", got.Prompt, []string{"consent"})
		if _, err := s.OAuthAuthRequestByCode("other"); !errors.Is(err, authx.ErrOAuthNotFound) {
			t.Fatalf("unknown code: want ErrOAuthNotFound, got %v", err)
		}

		if err := s.DeleteOAuthAuthRequest("r1"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.OAuthAuthRequest("r1"); !errors.Is(err, authx.ErrOAuthNotFound) {
			t.Fatalf("deleted request: want ErrOAuthNotFound, got %v", err)
		}
		if _, err := s.OAuthAuthRequestByCode("codehash"); !errors.Is(err, authx.ErrOAuthNotFound) {
			t.Fatalf("deleted request by code: want ErrOAuthNotFound, got %v", err)
		}
	})

	t.Run("grants", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.OAuthGrant("nope"); !errors.Is(err, authx.ErrOAuthNotFound) {
			t.Fatalf("absent grant: want ErrOAuthNotFound, got %v", err)
		}
		g := &authx.OAuthGrant{
			ID: "g1", ClientID: "c1", Subject: "u1", Scopes: []string{"openid"}, Resources: []string{},
			Ref: "ref-a", AuthTime: at(-time.Minute), CreatedAt: at(0), ExpiresAt: at(time.Hour),
		}
		if err := s.CreateOAuthGrant(g); err != nil {
			t.Fatal(err)
		}
		got, err := s.OAuthGrant("g1")
		if err != nil {
			t.Fatal(err)
		}
		if got.ClientID != "c1" || got.Subject != "u1" || got.Ref != "ref-a" || got.RevokedAt != nil {
			t.Fatalf("grant fields: %+v", got)
		}
		eqList(t, "Scopes", got.Scopes, []string{"openid"})
		eqList(t, "Resources (empty)", got.Resources, []string{})
		eqTime(t, "AuthTime", got.AuthTime, at(-time.Minute))
		eqTime(t, "CreatedAt", got.CreatedAt, at(0))
		eqTime(t, "ExpiresAt", got.ExpiresAt, at(time.Hour))

		// No end: ExpiresAt stays zero; nil lists stay nil.
		_ = s.CreateOAuthGrant(&authx.OAuthGrant{ID: "g0", ClientID: "c9", Subject: "u9", CreatedAt: at(0)})
		g0, _ := s.OAuthGrant("g0")
		if !g0.ExpiresAt.IsZero() || !g0.AuthTime.IsZero() {
			t.Fatalf("zero times must round-trip: %+v", g0)
		}
		eqList(t, "Scopes (nil)", g0.Scopes, nil)

		for _, x := range []authx.OAuthGrant{
			{ID: "g2", ClientID: "c1", Subject: "u1", Ref: "ref-b"},
			{ID: "g3", ClientID: "c1", Subject: "u2", Ref: "ref-b"},
			{ID: "g4", ClientID: "c2", Subject: "u1", Ref: "ref-c"},
			{ID: "g5", ClientID: "c1", Subject: "u1", Ref: "ref-c"},
		} {
			x.CreatedAt = at(0)
			if err := s.CreateOAuthGrant(&x); err != nil {
				t.Fatal(err)
			}
		}
		revoked := func(id string) bool {
			t.Helper()
			g, err := s.OAuthGrant(id)
			if err != nil {
				t.Fatal(err)
			}
			return g.RevokedAt != nil
		}

		if n, err := s.RevokeOAuthGrants(authx.OAuthGrantFilter{}, at(0)); n != 0 || err != nil {
			t.Fatalf("empty filter revokes nothing: n=%d err=%v", n, err)
		}
		if n, err := s.RevokeOAuthGrants(authx.OAuthGrantFilter{ID: "g1"}, at(time.Minute)); n != 1 || err != nil {
			t.Fatalf("by id: n=%d err=%v", n, err)
		}
		got, _ = s.OAuthGrant("g1")
		eqTimePtr(t, "RevokedAt", got.RevokedAt, tp(time.Minute))
		if n, _ := s.RevokeOAuthGrants(authx.OAuthGrantFilter{ID: "g1"}, at(2*time.Minute)); n != 0 {
			t.Fatalf("an already revoked grant is not counted again: n=%d", n)
		}
		got, _ = s.OAuthGrant("g1")
		eqTimePtr(t, "RevokedAt (kept)", got.RevokedAt, tp(time.Minute))

		if n, _ := s.RevokeOAuthGrants(authx.OAuthGrantFilter{ID: "g2", Ref: "ref-c"}, at(0)); n != 0 {
			t.Fatalf("every set field must match: n=%d", n)
		}
		if n, _ := s.RevokeOAuthGrants(authx.OAuthGrantFilter{Ref: "ref-b"}, at(0)); n != 2 || !revoked("g2") || !revoked("g3") {
			t.Fatalf("by ref: n=%d", n)
		}
		// c1+u1: g1 and g2 are already revoked, g5 is live → 1; g4 (other client) untouched.
		if n, _ := s.RevokeOAuthGrants(authx.OAuthGrantFilter{ClientID: "c1", Subject: "u1"}, at(0)); n != 1 || !revoked("g5") {
			t.Fatalf("by client+subject: n=%d", n)
		}
		if revoked("g4") || revoked("g0") {
			t.Fatal("unmatched grants must stay live")
		}
	})

	t.Run("access tokens", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.OAuthAccessToken("nope"); !errors.Is(err, authx.ErrOAuthNotFound) {
			t.Fatalf("absent token: want ErrOAuthNotFound, got %v", err)
		}
		in := &authx.OAuthAccessToken{ID: "a1", GrantID: "g1", ClientID: "c1", Subject: "u1",
			Scopes: []string{"openid", "email"}, ExpiresAt: at(time.Hour), CreatedAt: at(0)}
		if err := s.CreateOAuthAccessToken(in); err != nil {
			t.Fatal(err)
		}
		got, err := s.OAuthAccessToken("a1")
		if err != nil {
			t.Fatal(err)
		}
		if got.GrantID != "g1" || got.ClientID != "c1" || got.Subject != "u1" {
			t.Fatalf("token fields: %+v", got)
		}
		eqList(t, "Scopes", got.Scopes, []string{"openid", "email"})
		eqTime(t, "ExpiresAt", got.ExpiresAt, at(time.Hour))
		eqTime(t, "CreatedAt", got.CreatedAt, at(0))
		if err := s.DeleteOAuthAccessToken("a1"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.OAuthAccessToken("a1"); !errors.Is(err, authx.ErrOAuthNotFound) {
			t.Fatalf("deleted token: want ErrOAuthNotFound, got %v", err)
		}
	})

	t.Run("refresh tokens", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.OAuthRefreshToken("nope"); !errors.Is(err, authx.ErrOAuthNotFound) {
			t.Fatalf("absent token: want ErrOAuthNotFound, got %v", err)
		}
		in := &authx.OAuthRefreshToken{Hash: "h1", GrantID: "g1", ClientID: "c1", Subject: "u1",
			Scopes: []string{}, ExpiresAt: at(time.Hour), CreatedAt: at(0)}
		if err := s.CreateOAuthRefreshToken(in); err != nil {
			t.Fatal(err)
		}
		got, err := s.OAuthRefreshToken("h1")
		if err != nil {
			t.Fatal(err)
		}
		if got.GrantID != "g1" || got.ClientID != "c1" || got.Subject != "u1" || got.UsedAt != nil {
			t.Fatalf("token fields: %+v", got)
		}
		eqList(t, "Scopes (empty)", got.Scopes, []string{})
		eqTime(t, "ExpiresAt", got.ExpiresAt, at(time.Hour))
		eqTime(t, "CreatedAt", got.CreatedAt, at(0))

		if err := s.UseOAuthRefreshToken("h1", at(time.Minute)); err != nil {
			t.Fatalf("first use: %v", err)
		}
		if err := s.UseOAuthRefreshToken("h1", at(2*time.Minute)); !errors.Is(err, authx.ErrOAuthTokenUsed) {
			t.Fatalf("second use: want ErrOAuthTokenUsed, got %v", err)
		}
		got, _ = s.OAuthRefreshToken("h1")
		eqTimePtr(t, "UsedAt", got.UsedAt, tp(time.Minute))
		if err := s.UseOAuthRefreshToken("nope", at(0)); !errors.Is(err, authx.ErrOAuthNotFound) {
			t.Fatalf("unknown: want ErrOAuthNotFound, got %v", err)
		}
	})

	t.Run("refresh token use is atomic", func(t *testing.T) {
		s := newStore(t)
		if err := s.CreateOAuthRefreshToken(&authx.OAuthRefreshToken{Hash: "race", ExpiresAt: at(time.Hour), CreatedAt: at(0)}); err != nil {
			t.Fatal(err)
		}
		const n = 20
		errs := make([]error, n)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				errs[i] = s.UseOAuthRefreshToken("race", at(time.Duration(i)*time.Second))
			}(i)
		}
		close(start)
		wg.Wait()
		wins := 0
		for _, err := range errs {
			switch {
			case err == nil:
				wins++
			case !errors.Is(err, authx.ErrOAuthTokenUsed):
				t.Fatalf("a losing call must get ErrOAuthTokenUsed, got %v", err)
			}
		}
		if wins != 1 {
			t.Fatalf("exactly one concurrent use must win, got %d", wins)
		}
	})

	t.Run("signing keys", func(t *testing.T) {
		s := newStore(t)
		keys, err := s.OAuthSigningKeys()
		if err != nil || len(keys) != 0 {
			t.Fatalf("empty store: keys=%v err=%v", keys, err)
		}
		k1 := &authx.OAuthSigningKey{ID: "k1", Algorithm: "RS256", PrivatePEM: []byte("pem-1"), CreatedAt: at(0), RetiredAt: tp(time.Hour)}
		k2 := &authx.OAuthSigningKey{ID: "k2", Algorithm: "RS256", PrivatePEM: []byte("pem-2"), CreatedAt: at(time.Minute)}
		for _, k := range []*authx.OAuthSigningKey{k2, k1} {
			if err := s.AddOAuthSigningKey(k); err != nil {
				t.Fatal(err)
			}
		}
		keys, err = s.OAuthSigningKeys()
		if err != nil || len(keys) != 2 {
			t.Fatalf("keys=%v err=%v", keys, err)
		}
		if keys[0].ID != "k1" || keys[1].ID != "k2" {
			t.Fatalf("keys must be oldest first: %s, %s", keys[0].ID, keys[1].ID)
		}
		if keys[0].Algorithm != "RS256" || string(keys[0].PrivatePEM) != "pem-1" || string(keys[1].PrivatePEM) != "pem-2" {
			t.Fatalf("key fields: %+v", keys)
		}
		eqTime(t, "CreatedAt", keys[0].CreatedAt, at(0))
		eqTimePtr(t, "RetiredAt", keys[0].RetiredAt, tp(time.Hour))
		eqTimePtr(t, "RetiredAt (nil)", keys[1].RetiredAt, nil)

		// Re-adding by ID replaces.
		k2.RetiredAt = tp(2 * time.Hour)
		if err := s.AddOAuthSigningKey(k2); err != nil {
			t.Fatal(err)
		}
		keys, _ = s.OAuthSigningKeys()
		if len(keys) != 2 {
			t.Fatalf("re-adding must replace, got %d keys", len(keys))
		}
		eqTimePtr(t, "RetiredAt (retired)", keys[1].RetiredAt, tp(2*time.Hour))
	})

	t.Run("signing key retire and delete", func(t *testing.T) {
		s := newStore(t)
		for _, k := range []*authx.OAuthSigningKey{
			{ID: "k1", Algorithm: "RS256", PrivatePEM: []byte("pem-1"), CreatedAt: at(0)},
			{ID: "k2", Algorithm: "RS256", PrivatePEM: []byte("pem-2"), CreatedAt: at(time.Minute)},
		} {
			if err := s.AddOAuthSigningKey(k); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.RetireOAuthSigningKey("k1", at(time.Hour)); err != nil {
			t.Fatal(err)
		}
		// Retiring again keeps the first time (another replica retiring it must not extend its grace).
		if err := s.RetireOAuthSigningKey("k1", at(5*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := s.RetireOAuthSigningKey("nope", at(time.Hour)); !errors.Is(err, authx.ErrOAuthNotFound) {
			t.Fatalf("retiring an absent key = %v, want ErrOAuthNotFound", err)
		}
		keys, err := s.OAuthSigningKeys()
		if err != nil || len(keys) != 2 {
			t.Fatalf("keys=%v err=%v", keys, err)
		}
		eqTimePtr(t, "RetiredAt (k1)", keys[0].RetiredAt, tp(time.Hour))
		eqTimePtr(t, "RetiredAt (k2)", keys[1].RetiredAt, nil)
		if string(keys[0].PrivatePEM) != "pem-1" {
			t.Fatalf("retiring must keep the key: %+v", keys[0])
		}

		if err := s.DeleteOAuthSigningKey("k1"); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteOAuthSigningKey("k1"); err != nil {
			t.Fatalf("deleting is idempotent, got %v", err)
		}
		keys, _ = s.OAuthSigningKeys()
		if len(keys) != 1 || keys[0].ID != "k2" {
			t.Fatalf("after delete: %+v", keys)
		}
	})

	t.Run("delete expired", func(t *testing.T) {
		s := newStore(t)
		now := at(0)
		must := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		// Clients: stale dynamic (old last use), never-used dynamic (old creation), fresh dynamic,
		// recently used dynamic, and an old app-registered one (never removed).
		must(s.CreateOAuthClient(&authx.OAuthClient{ID: "dyn-stale", Dynamic: true, CreatedAt: at(-100 * time.Hour), LastUsedAt: at(-50 * time.Hour)}))
		must(s.CreateOAuthClient(&authx.OAuthClient{ID: "dyn-unused", Dynamic: true, CreatedAt: at(-50 * time.Hour)}))
		must(s.CreateOAuthClient(&authx.OAuthClient{ID: "dyn-new", Dynamic: true, CreatedAt: at(-time.Hour)}))
		must(s.CreateOAuthClient(&authx.OAuthClient{ID: "dyn-used", Dynamic: true, CreatedAt: at(-100 * time.Hour), LastUsedAt: at(-time.Hour)}))
		must(s.CreateOAuthClient(&authx.OAuthClient{ID: "app", CreatedAt: at(-100 * time.Hour)}))

		// Requests: requestsBefore = now-10m.
		must(s.SaveOAuthAuthRequest(&authx.OAuthAuthRequest{ID: "req-old", ClientID: "app", CreatedAt: at(-time.Hour)}))
		must(s.SaveOAuthAuthRequest(&authx.OAuthAuthRequest{ID: "req-new", ClientID: "app", CreatedAt: at(-time.Minute)}))

		// Grants.
		must(s.CreateOAuthGrant(&authx.OAuthGrant{ID: "g-live", ClientID: "app", CreatedAt: at(-time.Hour)}))
		must(s.CreateOAuthGrant(&authx.OAuthGrant{ID: "g-live-end", ClientID: "app", CreatedAt: at(-time.Hour), ExpiresAt: at(time.Hour)}))
		must(s.CreateOAuthGrant(&authx.OAuthGrant{ID: "g-expired", ClientID: "app", CreatedAt: at(-time.Hour), ExpiresAt: at(-time.Minute)}))
		must(s.CreateOAuthGrant(&authx.OAuthGrant{ID: "g-revoked", ClientID: "app", CreatedAt: at(-time.Hour), RevokedAt: tp(-time.Minute)}))
		must(s.CreateOAuthGrant(&authx.OAuthGrant{ID: "g-stale-client", ClientID: "dyn-stale", CreatedAt: at(-time.Hour)}))

		// Tokens: live/expired on a live grant, live ones on dead grants and on a stale client.
		tok := func(id, grant, client string, exp time.Duration) {
			must(s.CreateOAuthAccessToken(&authx.OAuthAccessToken{ID: id, GrantID: grant, ClientID: client, ExpiresAt: at(exp), CreatedAt: at(-time.Hour)}))
			must(s.CreateOAuthRefreshToken(&authx.OAuthRefreshToken{Hash: id, GrantID: grant, ClientID: client, ExpiresAt: at(exp), CreatedAt: at(-time.Hour)}))
		}
		tok("t-live", "g-live", "app", time.Hour)
		tok("t-expired", "g-live", "app", -time.Second)
		tok("t-of-expired", "g-expired", "app", time.Hour)
		tok("t-of-revoked", "g-revoked", "app", time.Hour)
		tok("t-of-stale", "g-stale-client", "dyn-stale", time.Hour)

		must(s.DeleteExpiredOAuth(now, at(-10*time.Minute), at(-24*time.Hour)))

		check := func(kind string, get func(string) error, keep, gone []string) {
			t.Helper()
			for _, id := range keep {
				if err := get(id); err != nil {
					t.Errorf("%s %q must be kept, got %v", kind, id, err)
				}
			}
			for _, id := range gone {
				if err := get(id); !errors.Is(err, authx.ErrOAuthNotFound) {
					t.Errorf("%s %q must be deleted, got %v", kind, id, err)
				}
			}
		}
		check("client", func(id string) error { _, err := s.OAuthClient(id); return err },
			[]string{"dyn-new", "dyn-used", "app"}, []string{"dyn-stale", "dyn-unused"})
		check("request", func(id string) error { _, err := s.OAuthAuthRequest(id); return err },
			[]string{"req-new"}, []string{"req-old"})
		check("grant", func(id string) error { _, err := s.OAuthGrant(id); return err },
			[]string{"g-live", "g-live-end"}, []string{"g-expired", "g-revoked", "g-stale-client"})
		gone := []string{"t-expired", "t-of-expired", "t-of-revoked", "t-of-stale"}
		check("access token", func(id string) error { _, err := s.OAuthAccessToken(id); return err },
			[]string{"t-live"}, gone)
		check("refresh token", func(id string) error { _, err := s.OAuthRefreshToken(id); return err },
			[]string{"t-live"}, gone)
	})
}
