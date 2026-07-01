package authx

import (
	"context"
	"reflect"
	"testing"

	"golang.org/x/oauth2"
)

func TestSocialOAuthRouting(t *testing.T) {
	a := &Authenticator{
		discordOAuth: &oauth2.Config{ClientID: "d"},
		oidcSocial: map[string]*oidcProvider{
			"microsoft": {oauth: &oauth2.Config{ClientID: "m"}},
			"gitlab":    {oauth: &oauth2.Config{ClientID: "g"}},
		},
	}
	if a.socialOAuth("discord") == nil {
		t.Fatal("discord should route")
	}
	if a.socialOAuth("microsoft") == nil || a.socialOAuth("gitlab") == nil {
		t.Fatal("generic OIDC providers should route")
	}
	if a.socialOAuth("nope") != nil {
		t.Fatal("unknown provider must be nil")
	}
	if !a.socialConfigured("discord") || !a.socialConfigured("microsoft") {
		t.Fatal("socialConfigured should see discord + generic OIDC")
	}
	if !a.anySocialConfigured() {
		t.Fatal("anySocialConfigured should be true when a generic provider is registered")
	}
	got := a.enabledSocialProviders()
	want := []string{"discord", "gitlab", "microsoft"} // sorted; google/github/facebook/apple unset
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("enabledSocialProviders: want %v, got %v", want, got)
	}
}

// enableOIDCSocial must skip entries missing a name / issuer / client id BEFORE any network
// discovery, so a misconfigured Config never registers a provider (and never dials out here).
func TestEnableOIDCSocialSkipsMisconfigured(t *testing.T) {
	a := &Authenticator{cfg: Config{SocialOIDC: []SocialOIDCProvider{
		{Name: "", Issuer: "https://x", ClientID: "c", ClientSecret: "s"},
		{Name: "y", Issuer: "", ClientID: "c", ClientSecret: "s"},
		{Name: "z", Issuer: "https://x", ClientID: "", ClientSecret: "s"},
	}}}
	a.enableOIDCSocial(context.Background())
	if len(a.oidcSocial) != 0 {
		t.Fatalf("misconfigured providers must be skipped, got %v", a.oidcSocial)
	}
}
