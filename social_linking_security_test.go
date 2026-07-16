package authx

// Adversarial verification of the social account-linking invariant shared by ALL social
// providers, driven through Authenticator.resolveSocialUser + facebookIdentity.
//
// The claim under attack: can ANY social path silently take over an UNVERIFIED local
// account, or accept an UNVERIFIED email?
//
// resolveSocialUser + facebookIdentity are unexported, so this test lives in package authx.
// The root package cannot import store/memory (memory imports authx -> import cycle), so we
// use linkFakeStore: a faithful, minimal re-implementation of the store/memory CredentialStore
// (and DirectoryStore) linking semantics. Its UserByEmail/UserByOAuth/LinkOAuth/CreateLocalUser/
// SetEmailVerified/UpsertExternalUser behave exactly as store/memory's Store does (see
// store/memory/memory.go findByEmail/CreateLocalUser/LinkOAuth/UpsertUserOnLogin), so the
// invariant we prove here is the invariant the shipped in-memory store enforces.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func refHMAC(key, msg string) string {
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

// ---- faithful fake of store/memory (avoids the authx<-memory import cycle) ----

type linkFakeUser struct {
	id            string
	sub           string
	email, name   string
	emailVerified bool
	disabled      bool
	hasPassword   bool
}

type linkFakeStore struct {
	seq   uint
	users map[string]*linkFakeUser
	oauth map[string]string // provider|subject -> userID
	// counters so tests can assert the exact code path taken.
	linkCalls   int
	createCalls int
	setVerified int
}

func newLinkFakeStore() *linkFakeStore {
	return &linkFakeStore{users: map[string]*linkFakeUser{}, oauth: map[string]string{}}
}

// nextID mints the fake's opaque string id (mirrors a store converting a numeric PK at its boundary).
func (s *linkFakeStore) nextID() string { s.seq++; return strconv.FormatUint(uint64(s.seq), 10) }

func lnorm(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

func (s *linkFakeStore) findByEmail(email string) *linkFakeUser {
	email = lnorm(email)
	for _, u := range s.users {
		if u.email == email {
			return u
		}
	}
	return nil
}

func (s *linkFakeStore) view(u *linkFakeUser) *AuthUser {
	return &AuthUser{ID: u.id, Sub: u.sub, Email: u.email, Name: u.name, EmailVerified: u.emailVerified, Disabled: u.disabled}
}

// seedUnverifiedLocal mirrors store/memory CreateLocalUser: a local: sub, EmailVerified=false.
func (s *linkFakeStore) seedUnverifiedLocal(email, name string) *linkFakeUser {
	u := &linkFakeUser{id: s.nextID(), sub: "local:squatter", email: lnorm(email), name: name, hasPassword: true}
	s.users[u.id] = u
	return u
}

func (s *linkFakeStore) seedVerified(sub, email, name string) *linkFakeUser {
	u := &linkFakeUser{id: s.nextID(), sub: sub, email: lnorm(email), name: name, emailVerified: true}
	s.users[u.id] = u
	return u
}

func (s *linkFakeStore) UserByEmail(email string) (*AuthUser, error) {
	if u := s.findByEmail(email); u != nil {
		return s.view(u), nil
	}
	return nil, ErrNoUser
}

func (s *linkFakeStore) UserBySub(sub string) (*AuthUser, error) {
	for _, u := range s.users {
		if u.sub == sub {
			return s.view(u), nil
		}
	}
	return nil, ErrNoUser
}

func (s *linkFakeStore) UserByOAuth(provider, subject string) (*AuthUser, error) {
	if uid, ok := s.oauth[provider+"|"+subject]; ok {
		if u := s.users[uid]; u != nil {
			return s.view(u), nil
		}
	}
	return nil, ErrNoUser
}

func (s *linkFakeStore) LinkOAuth(userID string, provider, subject, email string) error {
	s.linkCalls++
	if _, exists := s.oauth[provider+"|"+subject]; !exists {
		s.oauth[provider+"|"+subject] = userID
	}
	return nil
}

func (s *linkFakeStore) CreateLocalUser(email, name string) (*AuthUser, error) {
	s.createCalls++
	if s.findByEmail(email) != nil {
		return nil, ErrEmailConflict
	}
	u := &linkFakeUser{id: s.nextID(), sub: "local:new", email: lnorm(email), name: name}
	s.users[u.id] = u
	return s.view(u), nil
}

func (s *linkFakeStore) SetEmailVerified(userID string, verified bool) error {
	s.setVerified++
	if u := s.users[userID]; u != nil {
		u.emailVerified = verified
	}
	return nil
}

// Unused CredentialStore methods (present to satisfy the interface).
func (s *linkFakeStore) EnsureWebauthnHandle(string) ([]byte, error)    { return nil, ErrNoUser }
func (s *linkFakeStore) UserByWebauthnHandle([]byte) (*AuthUser, error) { return nil, ErrNoUser }
func (s *linkFakeStore) Passkeys(string) ([]Passkey, error)             { return nil, nil }
func (s *linkFakeStore) AddPasskey(string, Passkey) error               { return nil }
func (s *linkFakeStore) TouchPasskey([]byte, uint32) error              { return nil }
func (s *linkFakeStore) RemovePasskey(string, string) error             { return nil }
func (s *linkFakeStore) PasswordHash(string) (string, string, error)    { return "", "", ErrNoCredential }
func (s *linkFakeStore) SetPasswordHash(string, string, string) error   { return nil }
func (s *linkFakeStore) CreateToken(string, string, string, []byte, time.Time) error {
	return nil
}
func (s *linkFakeStore) ConsumeToken(string, []byte) (*TokenClaim, error) {
	return nil, ErrTokenInvalid
}
func (s *linkFakeStore) PeekToken(string, []byte) (*TokenClaim, error) {
	return nil, ErrTokenInvalid
}
func (s *linkFakeStore) RecordAudit(string, string, string, string, string, bool, string) {}
func (s *linkFakeStore) RecentFailures(string, time.Time) (int, error)                    { return 0, nil }
func (s *linkFakeStore) SetEmail(string, string) error                                    { return nil }
func (s *linkFakeStore) DeleteUser(string) error                                          { return nil }
func (s *linkFakeStore) RenamePasskey(string, string, string) error                       { return nil }
func (s *linkFakeStore) UnlinkOAuth(string, string) error                                 { return nil }
func (s *linkFakeStore) OAuthIdentities(string) ([]string, error)                         { return nil, nil }
func (s *linkFakeStore) CreateEmailOTP(string, string, []byte, time.Time, int) error      { return nil }
func (s *linkFakeStore) VerifyEmailOTP(string, string, []byte) (*TokenClaim, error) {
	return nil, ErrTokenInvalid
}

var _ CredentialStore = (*linkFakeStore)(nil)

// ---- (a) unverified squatter, no directory -> ErrEmailConflict (NO takeover) ----

func TestResolveSocialUser_UnverifiedSquatter_Refused(t *testing.T) {
	for _, provider := range []string{"google", "github", "facebook", "apple"} {
		t.Run(provider, func(t *testing.T) {
			s := newLinkFakeStore()
			squatter := s.seedUnverifiedLocal("victim@example.com", "Squatter")
			a := &Authenticator{creds: s, dir: nil} // dir == nil: no reclaim path

			u, err := a.resolveSocialUser(provider, "prov-subject-1", "victim@example.com", "Attacker")
			if !errors.Is(err, ErrEmailConflict) {
				t.Fatalf("unverified squatter takeover MUST be refused with ErrEmailConflict, got user=%+v err=%v", u, err)
			}
			// The squatter row must be UNTOUCHED and NOT linked to the social identity.
			if got := s.users[squatter.id]; got.sub != "local:squatter" || got.emailVerified {
				t.Fatalf("squatter mutated by refused takeover: sub=%q verified=%v", got.sub, got.emailVerified)
			}
			if _, ok := s.oauth[provider+"|prov-subject-1"]; ok {
				t.Fatalf("social identity must NOT be linked to the unverified squatter")
			}
			if s.linkCalls != 0 || s.setVerified != 0 || s.createCalls != 0 {
				t.Fatalf("no write should occur on refusal: link=%d setVerified=%d create=%d",
					s.linkCalls, s.setVerified, s.createCalls)
			}
		})
	}
}

// Case-fold attack: a squatter registered lowercase, social presents mixed case. The store
// normalizes email, so this must STILL be refused (not slip past as a "brand-new" email).
func TestResolveSocialUser_UnverifiedSquatter_CaseFold_Refused(t *testing.T) {
	s := newLinkFakeStore()
	s.seedUnverifiedLocal("victim@example.com", "Squatter")
	a := &Authenticator{creds: s, dir: nil}

	if _, err := a.resolveSocialUser("google", "sub-x", "Victim@Example.COM", "Attacker"); !errors.Is(err, ErrEmailConflict) {
		t.Fatalf("mixed-case email of an unverified squatter must be refused, got %v", err)
	}
	if s.createCalls != 0 {
		t.Fatalf("mixed-case email must NOT create a second (shadow) account")
	}
}

// ---- (b) verified existing user IS linked and returned ----

func TestResolveSocialUser_VerifiedUser_Linked(t *testing.T) {
	s := newLinkFakeStore()
	existing := s.seedVerified("local:realuser", "owner@example.com", "Owner")
	a := &Authenticator{creds: s, dir: nil}

	u, err := a.resolveSocialUser("github", "gh-42", "owner@example.com", "Owner From GitHub")
	if err != nil {
		t.Fatalf("verified user should be linked, got err %v", err)
	}
	if u.ID != existing.id {
		t.Fatalf("returned user id=%s, want existing %s", u.ID, existing.id)
	}
	if s.linkCalls != 1 {
		t.Fatalf("LinkOAuth should be called exactly once, got %d", s.linkCalls)
	}
	if uid, ok := s.oauth["github|gh-42"]; !ok || uid != existing.id {
		t.Fatalf("social identity should be linked to the verified user, got %s ok=%v", uid, ok)
	}
	if s.createCalls != 0 {
		t.Fatalf("must not create a new user when a verified one exists")
	}
	// Idempotency: a second resolve hits the natural key and does NOT re-link.
	if _, err := a.resolveSocialUser("github", "gh-42", "owner@example.com", "Owner"); err != nil {
		t.Fatalf("second resolve should succeed via natural key, got %v", err)
	}
	if s.linkCalls != 1 {
		t.Fatalf("second resolve must NOT re-link (natural key hit), link calls now %d", s.linkCalls)
	}
}

// ---- (c) brand-new email creates a user AND marks it verified ----

func TestResolveSocialUser_NewEmail_CreatesVerified(t *testing.T) {
	s := newLinkFakeStore()
	a := &Authenticator{creds: s, dir: nil}

	u, err := a.resolveSocialUser("google", "goog-99", "fresh@example.com", "Fresh Person")
	if err != nil {
		t.Fatalf("brand-new email should create a user, got %v", err)
	}
	if s.createCalls != 1 {
		t.Fatalf("CreateLocalUser should be called once, got %d", s.createCalls)
	}
	if s.linkCalls != 1 {
		t.Fatalf("LinkOAuth should be called once, got %d", s.linkCalls)
	}
	// The provider proved the address -> the new row must be marked verified.
	got := s.users[u.ID]
	if got == nil || !got.emailVerified {
		t.Fatalf("brand-new social user must be marked email-verified, got %+v", got)
	}
	if uid, ok := s.oauth["google|goog-99"]; !ok || uid != u.ID {
		t.Fatalf("new user must be linked to the social identity")
	}
}

// ---- Directory reclaim path (dir != nil): a VERIFIED social login reclaims the squatter ----

type reclaimDir struct {
	upserted *AuthUser
	sub      string
	verified bool
	called   int
}

func (d *reclaimDir) UpsertExternalUser(sub, email, name string, emailVerified bool) (*AuthUser, error) {
	d.called++
	d.sub, d.verified = sub, emailVerified
	d.upserted = &AuthUser{ID: "999", Sub: sub, Email: lnorm(email), Name: name, EmailVerified: emailVerified}
	return d.upserted, nil
}

// The remaining DirectoryStore methods are unused here.
func (d *reclaimDir) CreateGroup(string, string) (*Group, error)        { return nil, nil }
func (d *reclaimDir) Groups() ([]Group, error)                          { return nil, nil }
func (d *reclaimDir) GroupByName(string) (*Group, error)                { return nil, ErrNoGroup }
func (d *reclaimDir) DeleteGroup(string) error                          { return nil }
func (d *reclaimDir) AddUserToGroup(string, string) error               { return nil }
func (d *reclaimDir) RemoveUserFromGroup(string, string) error          { return nil }
func (d *reclaimDir) UserGroups(string) ([]Group, error)                { return nil, nil }
func (d *reclaimDir) GroupMembers(string) ([]AuthUser, error)           { return nil, nil }
func (d *reclaimDir) ListUsers() ([]AuthUser, error)                    { return nil, nil }
func (d *reclaimDir) UserByID(string) (*AuthUser, error)                { return nil, ErrNoUser }
func (d *reclaimDir) UserByEmail(string) (*AuthUser, error)             { return nil, ErrNoUser }
func (d *reclaimDir) SetUserDisabled(string, bool) error                { return nil }
func (d *reclaimDir) SetUserBan(string, bool, *time.Time, string) error { return nil }
func (d *reclaimDir) CreateAPIKey(string, []string, []string, string, []byte, *time.Time) (*APIKeyInfo, error) {
	return nil, nil
}
func (d *reclaimDir) APIKeyByHash([]byte) (*APIKeyInfo, error) { return nil, ErrNoCredential }
func (d *reclaimDir) ListAPIKeys() ([]APIKeyInfo, error)       { return nil, nil }
func (d *reclaimDir) RevokeAPIKey(string) error                { return nil }
func (d *reclaimDir) TouchAPIKey(string) error                 { return nil }

var _ DirectoryStore = (*reclaimDir)(nil)

func TestResolveSocialUser_DirectoryReclaimsVerified(t *testing.T) {
	s := newLinkFakeStore()
	s.seedUnverifiedLocal("victim@example.com", "Squatter")
	dir := &reclaimDir{}
	a := &Authenticator{creds: s, dir: dir}

	u, err := a.resolveSocialUser("facebook", "fb-7", "victim@example.com", "Real Owner")
	if err != nil {
		t.Fatalf("with a directory wired, a verified social login should reclaim, got %v", err)
	}
	if dir.called != 1 {
		t.Fatalf("UpsertExternalUser should be called once, got %d", dir.called)
	}
	if !dir.verified {
		t.Fatalf("reclaim must pass emailVerified=true (provider proved the email), got false")
	}
	if dir.sub != "social:facebook:fb-7" {
		t.Fatalf("reclaim sub should be social:facebook:fb-7, got %q", dir.sub)
	}
	if u.ID != "999" {
		t.Fatalf("resolve should return the reclaimed directory user, got %+v", u)
	}
}

// ---- (d) facebookIdentity: requires an email; returned email is verified; proof is HMAC-SHA256 ----

// rtFunc is a RoundTripper that returns a canned response for any request and captures the URL.
type rtFunc struct {
	lastURL string
	body    string
}

func (f *rtFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	f.lastURL = r.URL.String()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(f.body)),
		Request:    r,
	}, nil
}

func fbAuth(secret string) (*Authenticator, *oauth2.Config) {
	oc := &oauth2.Config{ClientID: "fb-app", ClientSecret: secret}
	return &Authenticator{creds: newLinkFakeStore()}, oc
}

func TestFacebookIdentity_RequiresEmail(t *testing.T) {
	rt := &rtFunc{body: `{"id":"12345","name":"No Email User"}`} // NO email field
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Transport: rt})
	a, oc := fbAuth("app-secret")

	sub, email, name, err := a.facebookIdentity(ctx, oc, &oauth2.Token{AccessToken: "AT"})
	if err == nil {
		t.Fatalf("facebookIdentity must error when the provider returns no email; got sub=%q email=%q name=%q", sub, email, name)
	}
	if !strings.Contains(err.Error(), "no email") {
		t.Fatalf("error should mention the missing email, got %v", err)
	}
}

func TestFacebookIdentity_EmailTreatedAsVerified(t *testing.T) {
	rt := &rtFunc{body: `{"id":"fb-abc","name":"Ada","email":"ada@fb.example"}`}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Transport: rt})
	a, oc := fbAuth("app-secret")

	sub, email, name, err := a.facebookIdentity(ctx, oc, &oauth2.Token{AccessToken: "the-access-token"})
	if err != nil {
		t.Fatalf("facebookIdentity with an email should succeed, got %v", err)
	}
	if sub != "fb-abc" || email != "ada@fb.example" || name != "Ada" {
		t.Fatalf("identity mismatch: sub=%q email=%q name=%q", sub, email, name)
	}

	// Prove "treated as verified": feed the identity into resolveSocialUser on a store that has
	// an UNVERIFIED squatter for the SAME email. If FB emails were NOT treated as verified this
	// would go to the squatter branch and be refused. Instead it must LINK (verified branch).
	s := newLinkFakeStore()
	// Seed a VERIFIED user with this email so the "verified => link" branch runs (this proves
	// resolveSocialUser links a FB identity to an existing verified account without takeover risk).
	existing := s.seedVerified("local:owner", email, "Owner")
	ra := &Authenticator{creds: s, dir: nil}
	u, rerr := ra.resolveSocialUser("facebook", sub, email, name)
	if rerr != nil {
		t.Fatalf("resolveSocialUser with FB identity should link to verified owner, got %v", rerr)
	}
	if u.ID != existing.id {
		t.Fatalf("FB identity should link to existing verified owner id=%s, got %s", existing.id, u.ID)
	}

	// appsecret_proof must be the standard HMAC-SHA256 of the ACCESS TOKEN keyed by the APP SECRET.
	want := hmacSHA256Hex("app-secret", "the-access-token")
	if !strings.Contains(rt.lastURL, "appsecret_proof="+want) {
		t.Fatalf("appsecret_proof mismatch.\n url=%s\n want proof=%s", rt.lastURL, want)
	}
	// And it must NOT be keyed the other way round (token as key) — a common mistake.
	wrong := hmacSHA256Hex("the-access-token", "app-secret")
	if strings.Contains(rt.lastURL, "appsecret_proof="+wrong) {
		t.Fatalf("appsecret_proof is keyed backwards (token as HMAC key)")
	}
}

// Independently pin hmacSHA256Hex to the crypto/hmac + crypto/sha256 reference so a future
// refactor of the proof helper can't silently change the algorithm.
func TestHMACSHA256Hex_MatchesStdlib(t *testing.T) {
	key, msg := "app-secret", "the-access-token"
	if got := hmacSHA256Hex(key, msg); got != refHMAC(key, msg) {
		t.Fatalf("hmacSHA256Hex=%s, want stdlib HMAC-SHA256 %s", got, refHMAC(key, msg))
	}
}
