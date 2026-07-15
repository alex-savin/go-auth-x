package mailer

import (
	"strings"
	"testing"
)

func TestFromEnv_Defaults(t *testing.T) {
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_PORT", "") // exercise the default
	t.Setenv("SMTP_USER", "bot@example.com")
	t.Setenv("SMTP_PASS", "secret")
	t.Setenv("SMTP_FROM", "") // exercise the "defaults to user" path

	s := FromEnv()
	if s.host != "smtp.example.com" {
		t.Fatalf("host = %q", s.host)
	}
	if s.port != "587" {
		t.Fatalf("port must default to 587, got %q", s.port)
	}
	if s.from != "bot@example.com" {
		t.Fatalf("from must default to user, got %q", s.from)
	}
	if !s.Configured() {
		t.Fatal("a fully-populated sender must be Configured")
	}
}

func TestConfigured(t *testing.T) {
	var nilS *Sender
	if nilS.Configured() {
		t.Fatal("a nil sender must not be Configured")
	}
	if (&Sender{}).Configured() {
		t.Fatal("the zero value must not be Configured")
	}
	if (&Sender{host: "h", user: "u", pass: "p"}).Configured() {
		t.Fatal("a sender missing `from` must not be Configured")
	}
	if !(&Sender{host: "h", user: "u", pass: "p", from: "f"}).Configured() {
		t.Fatal("a complete sender must be Configured")
	}
}

func TestSanitizeHeader(t *testing.T) {
	cases := map[string]string{
		"clean subject":            "clean subject",
		"line1\r\nBcc: evil@x.com": "line1", // CRLF header injection
		"a\nb":                     "a",     // bare LF
		"a\rb":                     "a",     // bare CR
	}
	for in, want := range cases {
		if got := sanitizeHeader(in); got != want {
			t.Fatalf("sanitizeHeader(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildMIME_StructureAndInjection(t *testing.T) {
	msg := string(buildMIME("from@x.com", "to@x.com", "Hi\r\nBcc: evil@x.com", "text-body", "<b>html-body</b>"))

	// A CRLF-injected extra header in the subject must be neutralized.
	if strings.Contains(msg, "Bcc:") {
		t.Fatalf("injected header leaked into the message:\n%s", msg)
	}
	for _, want := range []string{
		"From: from@x.com\r\n",
		"To: to@x.com\r\n",
		"Subject: Hi\r\n",
		"MIME-Version: 1.0",
		"multipart/alternative; boundary=",
		"Content-Type: text/plain; charset=\"UTF-8\"",
		"Content-Type: text/html; charset=\"UTF-8\"",
		"text-body",
		"<b>html-body</b>",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("MIME message is missing %q:\n%s", want, msg)
		}
	}
}

func TestSend_NotConfigured(t *testing.T) {
	if err := (&Sender{}).Send("to@x.com", "s", "<p>h</p>", "t"); err == nil {
		t.Fatal("Send on an unconfigured sender must error rather than dial")
	}
}
