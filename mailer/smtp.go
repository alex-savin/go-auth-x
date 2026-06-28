// Package email is a minimal SMTP sender for the in-app auth flows (magic-link, email
// verification, password reset, invites). It speaks explicit STARTTLS to the configured
// server (e.g. smtp.gmail.com:587) using an app password from the environment, so the
// credential never crosses the wire in cleartext. It satisfies auth.Mailer.
package mailer

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// Sender holds SMTP configuration. The zero value (no host) is !Configured(), so email
// methods disable cleanly when SMTP isn't set up.
type Sender struct {
	host string // SMTP_HOST, e.g. smtp.gmail.com
	port string // SMTP_PORT, e.g. 587
	user string // SMTP_USER (the authenticating account)
	pass string // SMTP_PASS (app password)
	from string // SMTP_FROM (defaults to user)
}

// FromEnv builds a Sender from SMTP_* environment variables.
func FromEnv() *Sender {
	s := &Sender{
		host: strings.TrimSpace(os.Getenv("SMTP_HOST")),
		port: strings.TrimSpace(os.Getenv("SMTP_PORT")),
		user: strings.TrimSpace(os.Getenv("SMTP_USER")),
		pass: os.Getenv("SMTP_PASS"),
		from: strings.TrimSpace(os.Getenv("SMTP_FROM")),
	}
	if s.port == "" {
		s.port = "587"
	}
	if s.from == "" {
		s.from = s.user
	}
	return s
}

// Configured reports whether enough is set to send mail.
func (s *Sender) Configured() bool {
	return s != nil && s.host != "" && s.user != "" && s.pass != "" && s.from != ""
}

// Send delivers a multipart text+html message over STARTTLS. TLS is required.
func (s *Sender) Send(to, subject, htmlBody, textBody string) error {
	if !s.Configured() {
		return fmt.Errorf("email: SMTP not configured")
	}
	addr := net.JoinHostPort(s.host, s.port)
	msg := buildMIME(s.from, to, subject, textBody, htmlBody)

	c, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("email: dial %s: %w", addr, err)
	}
	defer c.Close()
	if err := c.Hello(clientHostname()); err != nil {
		return fmt.Errorf("email: helo: %w", err)
	}
	if ok, _ := c.Extension("STARTTLS"); !ok {
		return fmt.Errorf("email: server %s does not support STARTTLS", s.host)
	}
	if err := c.StartTLS(&tls.Config{ServerName: s.host}); err != nil {
		return fmt.Errorf("email: starttls: %w", err)
	}
	if err := c.Auth(smtp.PlainAuth("", s.user, s.pass, s.host)); err != nil {
		return fmt.Errorf("email: auth: %w", err)
	}
	if err := c.Mail(s.from); err != nil {
		return fmt.Errorf("email: mail from: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("email: rcpt to: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("email: data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// buildMIME assembles a multipart/alternative (text + html) message.
func buildMIME(from, to, subject, text, html string) []byte {
	boundary := fmt.Sprintf("sweep-%d", time.Now().UnixNano())
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n\r\n")
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=\"UTF-8\"\r\n\r\n")
	b.WriteString(text + "\r\n\r\n")
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/html; charset=\"UTF-8\"\r\n\r\n")
	b.WriteString(html + "\r\n\r\n")
	b.WriteString("--" + boundary + "--\r\n")
	return []byte(b.String())
}

func clientHostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "localhost"
}
