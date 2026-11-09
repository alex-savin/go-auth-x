// Command demo serves go-auth-x with its surfaces wired against the in-memory store: passwords,
// passkeys, email links and codes, 2FA, organizations, the admin API, SCIM, and the OAuth/OIDC
// provider. It is a runnable example and the target the security workflow scans with OWASP ZAP —
// not for production: all state is in memory and emails are printed instead of sent.
//
//	go run ./examples/demo            # http://127.0.0.1:8080
//	DEMO_ADDR=:9000 go run ./examples/demo
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/oidcprovider"
	"github.com/alex-savin/go-auth-x/scim"
	"github.com/alex-savin/go-auth-x/store/memory"
)

// printMailer "sends" auth emails by printing them, so a demo user can follow the links.
type printMailer struct{}

func (printMailer) Configured() bool { return true }
func (printMailer) Send(to, subject, _, text string) error {
	log.Printf("demo mail to %s — %s\n%s", to, subject, text)
	return nil
}

func randomKey() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return b
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	ctx := context.Background()
	addr := envOr("DEMO_ADDR", "127.0.0.1:8080")
	appURL := strings.TrimRight(envOr("APP_URL", "http://"+addr), "/")
	secret := []byte(os.Getenv("SESSION_SECRET"))
	if len(secret) < 32 {
		secret = []byte(hex.EncodeToString(randomKey())) // a fresh key per run: sessions don't outlive it
	}

	store := memory.New()
	authn, err := authx.New(ctx, authx.Config{
		SessionSecret: secret, AppURL: appURL, OwnerEmail: "owner@example.com", BrandName: "go-auth-x demo",
		PublicPath: func(p string) bool { return p == "/" || p == "/login" || p == "/welcome" || p == "/consent" },
	})
	if err != nil {
		log.Fatal(err)
	}
	defer authn.Close()
	authn.SetCredentialStore(store)
	authn.SetDirectoryStore(store)
	authn.SetTwoFactorStore(store)
	authn.SetSessionStore(store)
	authn.SetOrgStore(store)
	authn.SetMailer(printMailer{})
	authn.SetAuthorizer(store.Authorizer())
	authn.SetLocalEnabled(true)

	provider, err := oidcprovider.New(ctx, oidcprovider.Config{
		Issuer: appURL, Auth: authn, Store: store, CryptoKey: randomKey(),
		Scopes: []string{"notes:read"}, Resources: []string{appURL + "/api/notes"},
		ConsentURL:   func(id string) string { return "/consent?request=" + id },
		Registration: true, Insecure: strings.HasPrefix(appURL, "http://"),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer provider.Close()

	mux := http.NewServeMux()
	mux.Handle("/auth/", authn.Handler())
	for _, pat := range provider.Patterns() {
		mux.Handle(pat, provider.Handler())
	}
	mux.Handle("/scim/v2/", http.StripPrefix("/scim/v2",
		scim.NewServer(store, func(t string) bool { return authn.ValidateAPIKeyScope(t, "scim") }).Handler()))

	app := http.NewServeMux()
	app.HandleFunc("GET /{$}", page(indexHTML))
	app.HandleFunc("GET /login", page(loginHTML))   // where the library's emails send people
	app.HandleFunc("GET /welcome", page(loginHTML)) // where the gate sends them
	app.HandleFunc("GET /consent", page(consentHTML))
	app.HandleFunc("GET /api/notes", func(w http.ResponseWriter, r *http.Request) {
		sub, email, _ := authx.SessionFromRequest(r)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, "{\"sub\":%q,\"email\":%q,\"notes\":[]}\n", sub, email)
	})
	mux.Handle("/", authn.GateHTTP(authn.CSRFHTTP(app)))

	srv := &http.Server{Addr: addr, Handler: securityHeaders(mux), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("go-auth-x demo on %s", appURL)
	log.Fatal(srv.ListenAndServe())
}

// securityHeaders sets the headers an app serving the library's pages should send.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Embedder-Policy", "require-corp")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func page(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, "<!doctype html><html lang=en><meta charset=utf-8><title>go-auth-x demo</title>%s</html>", body)
	}
}

// The pages are plain links and forms, so a crawler (and a person) can reach every public endpoint.
const indexHTML = `<h1>go-auth-x demo</h1>
<ul>
<li><a href="/login">Sign in / sign up</a></li>
<li><a href="/auth/config">/auth/config</a> · <a href="/auth/me">/auth/me</a> · <a href="/auth/logout">/auth/logout</a></li>
<li><a href="/api/notes">/api/notes</a> (signed-in only)</li>
<li><a href="/.well-known/openid-configuration">OIDC discovery</a> · <a href="/.well-known/oauth-authorization-server">OAuth metadata</a> · <a href="/oauth/keys">JWKS</a></li>
<li><a href="/oauth/authorize?response_type=code&amp;client_id=demo&amp;redirect_uri=http%3A%2F%2F127.0.0.1%3A9%2Fcb&amp;state=s&amp;code_challenge=x&amp;code_challenge_method=S256">/oauth/authorize</a></li>
<li><a href="/auth/email/login?token=example">magic link</a> · <a href="/auth/email/verify?token=example">verify link</a></li>
<li><a href="/scim/v2/ServiceProviderConfig">SCIM</a> (Bearer key)</li>
</ul>`

const loginHTML = `<h1>Sign in</h1>
<form method=post action="/auth/password/login"><input name=email type=email><input name=password type=password><button>Sign in</button></form>
<h2>Sign up</h2>
<form method=post action="/auth/password/signup"><input name=email type=email><input name=password type=password><button>Sign up</button></form>
<h2>Email me a link</h2>
<form method=post action="/auth/email/request"><input name=email type=email><button>Send</button></form>
<h2>Email me a code</h2>
<form method=post action="/auth/email-otp/send"><input name=email type=email><button>Send</button></form>
<form method=post action="/auth/email-otp/verify"><input name=email type=email><input name=code><button>Verify</button></form>
<h2>Forgot password</h2>
<form method=post action="/auth/password/reset/request"><input name=email type=email><button>Reset</button></form>`

const consentHTML = `<h1>Allow access?</h1><p>The app renders its consent screen from <code>GET /oauth/consent?id=…</code>.</p>`
