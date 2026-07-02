package authx

import (
	"fmt"
	"html"
	"log"
	"net/url"
	"strings"
)

// baseURL returns the app's public origin for email links and post-login redirects:
// APP_URL if set, else the OIDC RedirectURL's origin.
func (a *Authenticator) baseURL() string {
	if a.cfg.AppURL != "" {
		return a.cfg.AppURL
	}
	if u, err := url.Parse(a.cfg.RedirectURL); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return ""
}

// brandName is the label shown in auth emails and used as the WebAuthn RP display-name default.
func (a *Authenticator) brandName() string {
	if a.cfg.BrandName != "" {
		return a.cfg.BrandName
	}
	return "go-auth-x"
}

// normEmail normalizes an email for storage/comparison.
func normEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

// validEmail is a light syntactic check (exactly one @, non-empty local + domain, no spaces).
func validEmail(e string) bool {
	if len(e) == 0 || len(e) > 254 || strings.ContainsAny(e, " \t\r\n") {
		return false
	}
	at := strings.IndexByte(e, '@')
	return at > 0 && at < len(e)-1 && strings.Count(e, "@") == 1 && strings.Contains(e[at:], ".")
}

// sendAuthEmail renders the branded shell around a heading/intro/CTA and sends it. Callers
// generally swallow the error (anti-enumeration: the user-facing response is identical
// whether or not mail was actually sent).
func (a *Authenticator) sendAuthEmail(to, subject, heading, intro, ctaLabel, ctaURL, footer string) error {
	if a.email == nil || !a.email.Configured() {
		return fmt.Errorf("email not configured")
	}
	htmlBody := emailShell(a.brandName(), heading, intro, ctaLabel, ctaURL, footer)
	textBody := intro + "\n\n" + ctaLabel + ":\n" + ctaURL + "\n\n" + footer
	if err := a.email.Send(to, subject, htmlBody, textBody); err != nil {
		log.Printf("auth: email %q to %s FAILED: %v", subject, to, err)
		return err
	}
	log.Printf("auth: email %q sent to %s", subject, to)
	return nil
}

// emailShell wraps the message in the dark branded chrome (inline styles for mail clients). ctaURL is
// HTML-escaped like every other interpolated value so it can't break out of the href attribute.
func emailShell(brand, heading, intro, ctaLabel, ctaURL, footer string) string {
	return `<!doctype html><html><body style="margin:0;background:#0b0f17;padding:24px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <div style="max-width:440px;margin:0 auto;background:#111826;border:1px solid #1f2a3a;border-radius:14px;padding:28px;color:#e2e8f0;">
    <div style="font-weight:700;font-size:16px;margin-bottom:18px;">` + html.EscapeString(brand) + `</div>
    <h1 style="font-size:19px;margin:0 0 12px;color:#f1f5f9;">` + html.EscapeString(heading) + `</h1>
    <p style="color:#94a3b8;font-size:14px;line-height:1.55;margin:0 0 22px;">` + html.EscapeString(intro) + `</p>
    <a href="` + html.EscapeString(ctaURL) + `" style="display:inline-block;background:#059669;color:#fff;text-decoration:none;padding:11px 22px;border-radius:9px;font-weight:600;font-size:14px;">` + html.EscapeString(ctaLabel) + `</a>
    <p style="color:#64748b;font-size:12px;line-height:1.5;margin:24px 0 0;">` + html.EscapeString(footer) + `</p>
  </div></body></html>`
}
