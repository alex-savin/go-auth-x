package scim

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	authx "github.com/alex-savin/go-auth-x"
)

// This file implements SCIM 2.0 filtering (RFC 7644 §3.4.2.2) with boolean composition — `and`,
// `or`, `not(...)`, and parentheses — over attribute expressions (`attr op value` / `attr pr`),
// plus the attribute getters used for both filtering and sorting. Supported operators:
// eq, ne, co, sw, ew, pr. Not supported: valuePath (`emails[type eq "work"]`), gt/ge/lt/le.

// attrGetter resolves a resource attribute by name (case-insensitive) to its value + presence.
type attrGetter func(attr string) (value string, present bool)

// pred is a compiled filter predicate.
type pred func(get attrGetter) bool

func toID(id uint) string { return strconv.FormatUint(uint64(id), 10) }

// --- attribute getters (users + groups) ---

func userAttr(u *authx.AuthUser, attr string) (string, bool) {
	switch strings.ToLower(attr) {
	case "id":
		return toID(u.ID), true
	case "username", "emails", "emails.value", "externalid":
		return u.Email, u.Email != ""
	case "name", "name.formatted", "displayname":
		return u.Name, u.Name != ""
	case "active":
		return strconv.FormatBool(!u.Disabled), true
	}
	return "", false
}

func userGetter(u *authx.AuthUser) attrGetter {
	return func(a string) (string, bool) { return userAttr(u, a) }
}

func groupAttr(g *authx.Group, attr string) (string, bool) {
	switch strings.ToLower(attr) {
	case "id":
		return toID(g.ID), true
	case "displayname":
		return g.Name, g.Name != ""
	}
	return "", false
}

func groupGetter(g *authx.Group) attrGetter {
	return func(a string) (string, bool) { return groupAttr(g, a) }
}

// --- sorting ---

func sortUsers(users []authx.AuthUser, sortBy, sortOrder string) {
	if sortBy == "" {
		return
	}
	desc := strings.EqualFold(sortOrder, "descending")
	sort.SliceStable(users, func(i, j int) bool {
		a, _ := userAttr(&users[i], sortBy)
		b, _ := userAttr(&users[j], sortBy)
		return less(a, b, desc)
	})
}

func sortGroups(groups []authx.Group, sortBy, sortOrder string) {
	if sortBy == "" {
		return
	}
	desc := strings.EqualFold(sortOrder, "descending")
	sort.SliceStable(groups, func(i, j int) bool {
		a, _ := groupAttr(&groups[i], sortBy)
		b, _ := groupAttr(&groups[j], sortBy)
		return less(a, b, desc)
	})
}

func less(a, b string, desc bool) bool {
	a, b = strings.ToLower(a), strings.ToLower(b)
	if desc {
		return a > b
	}
	return a < b
}

// --- tokenizer ---

type tokKind int

const (
	tkWord tokKind = iota
	tkString
	tkLParen
	tkRParen
	tkEOF
)

type token struct {
	kind tokKind
	val  string
}

func tokenize(s string) ([]token, error) {
	var toks []token
	for i, n := 0, len(s); i < n; {
		switch c := s[i]; {
		case c == ' ' || c == '\t':
			i++
		case c == '(':
			toks = append(toks, token{tkLParen, "("})
			i++
		case c == ')':
			toks = append(toks, token{tkRParen, ")"})
			i++
		case c == '"':
			var b strings.Builder
			j := i + 1
			for j < n && s[j] != '"' {
				if s[j] == '\\' && j+1 < n { // \" and \\ escapes
					j++
				}
				b.WriteByte(s[j])
				j++
			}
			if j >= n {
				return nil, fmt.Errorf("unterminated string literal")
			}
			toks = append(toks, token{tkString, b.String()})
			i = j + 1
		default:
			j := i
			for j < n && s[j] != ' ' && s[j] != '\t' && s[j] != '(' && s[j] != ')' {
				j++
			}
			toks = append(toks, token{tkWord, s[i:j]})
			i = j
		}
	}
	return append(toks, token{tkEOF, ""}), nil
}

// --- recursive-descent parser: or < and < not < primary ---

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) next() token { t := p.toks[p.pos]; p.pos++; return t }

func isKw(t token, kw string) bool { return t.kind == tkWord && strings.EqualFold(t.val, kw) }

// compileFilter parses a SCIM filter expression into a predicate, or returns an error on malformed
// input (the caller maps that to a 400 with scimType "invalidFilter").
func compileFilter(s string) (pred, error) {
	toks, err := tokenize(s)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	pr, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tkEOF {
		return nil, fmt.Errorf("unexpected token %q", p.peek().val)
	}
	return pr, nil
}

func (p *parser) parseOr() (pred, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for isKw(p.peek(), "or") {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		l, r := left, right
		left = func(g attrGetter) bool { return l(g) || r(g) }
	}
	return left, nil
}

func (p *parser) parseAnd() (pred, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for isKw(p.peek(), "and") {
		p.next()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		l, r := left, right
		left = func(g attrGetter) bool { return l(g) && r(g) }
	}
	return left, nil
}

func (p *parser) parseNot() (pred, error) {
	if isKw(p.peek(), "not") {
		p.next()
		if p.peek().kind != tkLParen {
			return nil, fmt.Errorf("expected '(' after not")
		}
		p.next()
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tkRParen {
			return nil, fmt.Errorf("expected ')'")
		}
		p.next()
		return func(g attrGetter) bool { return !inner(g) }, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (pred, error) {
	if p.peek().kind == tkLParen {
		p.next()
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tkRParen {
			return nil, fmt.Errorf("expected ')'")
		}
		p.next()
		return inner, nil
	}
	return p.parseAttrExp()
}

func (p *parser) parseAttrExp() (pred, error) {
	at := p.next()
	if at.kind != tkWord {
		return nil, fmt.Errorf("expected an attribute, got %q", at.val)
	}
	opTok := p.next()
	if opTok.kind != tkWord {
		return nil, fmt.Errorf("expected an operator after %q", at.val)
	}
	attr, op := strings.ToLower(at.val), strings.ToLower(opTok.val)
	if op == "pr" {
		return func(g attrGetter) bool { v, ok := g(attr); return ok && v != "" }, nil
	}
	switch op {
	case "eq", "ne", "co", "sw", "ew":
	default:
		return nil, fmt.Errorf("unsupported operator %q", opTok.val)
	}
	vt := p.next()
	if vt.kind != tkWord && vt.kind != tkString {
		return nil, fmt.Errorf("expected a value after %q %q", at.val, opTok.val)
	}
	want := vt.val
	return func(g attrGetter) bool {
		have, present := g(attr)
		return matchAttr(have, present, op, want)
	}, nil
}

func matchAttr(have string, present bool, op, want string) bool {
	h, w := strings.ToLower(have), strings.ToLower(want)
	switch op {
	case "eq":
		return present && h == w
	case "ne":
		return !(present && h == w)
	case "co":
		return present && strings.Contains(h, w)
	case "sw":
		return present && strings.HasPrefix(h, w)
	case "ew":
		return present && strings.HasSuffix(h, w)
	}
	return false
}
