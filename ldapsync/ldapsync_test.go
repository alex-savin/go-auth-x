package ldapsync

import (
	"strings"
	"testing"
)

func TestWithDefaults(t *testing.T) {
	c := New(Config{}, nil).cfg
	if c.UserFilter != "(objectClass=person)" || c.AttrUID != "uid" || c.AttrEmail != "mail" ||
		c.AttrName != "cn" || c.GroupFilter != "(objectClass=groupOfNames)" ||
		c.AttrGroupName != "cn" || c.AttrGroupMember != "member" {
		t.Fatalf("OpenLDAP defaults not applied: %+v", c)
	}
	// Explicit (e.g. Active Directory) values must be preserved.
	ad := New(Config{AttrUID: "sAMAccountName", AttrGroupMember: "memberUid", UserFilter: "(objectClass=user)"}, nil).cfg
	if ad.AttrUID != "sAMAccountName" || ad.AttrGroupMember != "memberUid" || ad.UserFilter != "(objectClass=user)" {
		t.Fatalf("explicit values overwritten: %+v", ad)
	}
}

func TestNormalizeDN(t *testing.T) {
	a := normalizeDN("CN=Alice,  OU=People, DC=Example,DC=com")
	b := normalizeDN("cn=alice,ou=people,dc=example,dc=com")
	if a != b {
		t.Fatalf("DNs differing only in case/spacing must normalize equal:\n %q\n %q", a, b)
	}
	// An unparseable value falls back to a trimmed, lower-cased form.
	if got := normalizeDN("  BOGUS  "); got != "bogus" {
		t.Fatalf("fallback normalization = %q, want %q", got, "bogus")
	}
}

func TestResolveMember(t *testing.T) {
	byDN := map[string]string{normalizeDN("cn=alice,dc=x"): "1"}
	byUID := map[string]string{"bob": "2"}

	if id, ok := resolveMember("CN=Alice, DC=X", byDN, byUID); !ok || id != "1" {
		t.Fatalf("a DN member must resolve via byDN (normalized), got id=%s ok=%v", id, ok)
	}
	if id, ok := resolveMember("bob", byDN, byUID); !ok || id != "2" {
		t.Fatalf("a bare uid (posixGroup) must resolve via byUID, got id=%s ok=%v", id, ok)
	}
	if _, ok := resolveMember("cn=ghost,dc=x", byDN, byUID); ok {
		t.Fatal("an unknown DN must not resolve")
	}
	if _, ok := resolveMember("nobody", byDN, byUID); ok {
		t.Fatal("an unknown uid must not resolve")
	}
}

func TestDial_RefusesCleartextBind(t *testing.T) {
	// A bind password over plain ldap:// with no StartTLS must be refused BEFORE any network I/O
	// (RFC 4513 §5.1.3).
	s := New(Config{URL: "ldap://ldap.example.com:389", BindDN: "cn=svc,dc=x", BindPassword: "secret"}, nil)
	_, err := s.dial()
	if err == nil || !strings.Contains(err.Error(), "cleartext") {
		t.Fatalf("dial must refuse a cleartext bind, got %v", err)
	}
}

func TestDial_InvalidURL(t *testing.T) {
	s := New(Config{URL: "://not a url"}, nil)
	if _, err := s.dial(); err == nil {
		t.Fatal("dial must error on an unparseable URL")
	}
}
