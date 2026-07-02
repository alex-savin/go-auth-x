package scim

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	authx "github.com/alex-savin/go-auth-x"
)

// This file implements SCIM 2.0 filtering (RFC 7644 §3.4.2.2): boolean composition (`and`, `or`,
// `not(...)`, parentheses), attribute expressions (`attr op value` / `attr pr`), and valuePath
// (`emails[type eq "work"]`). Operators: eq, ne, co, sw, ew, gt, ge, lt, le, pr (gt/ge/lt/le are
// lexicographic — our attributes are strings). Plus the attribute getters used for sorting.

// attrGetter resolves a resource attribute by name (case-insensitive) to its value + presence.
type attrGetter func(attr string) (value string, present bool)

// pred is a compiled filter predicate evaluated against a resource.
type pred func(r resource) bool

// resource exposes a SCIM resource for filtering: scalar attributes, plus multi-valued attributes
// (emails, members) so valuePath expressions like emails[type eq "work"] can be evaluated.
type resource struct {
	scalar attrGetter
	multi  func(attr string) []elem
}

// elem is one sub-value of a multi-valued attribute, addressable by its lower-cased sub-attributes.
type elem map[string]string

// asResource wraps a sub-value so an inner valuePath filter can be evaluated against it.
func (e elem) asResource() resource {
	return resource{
		scalar: func(a string) (string, bool) { v, ok := e[strings.ToLower(a)]; return v, ok },
		multi:  func(string) []elem { return nil },
	}
}

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

// userResource / groupResource build a filterable resource. multi() exposes the multi-valued
// attributes for valuePath: users' emails (one element), groups' members (loaded lazily).
func userResource(u *authx.AuthUser) resource {
	return resource{
		scalar: userGetter(u),
		multi: func(attr string) []elem {
			if strings.EqualFold(attr, "emails") && u.Email != "" {
				return []elem{{"value": u.Email, "primary": "true"}}
			}
			return nil
		},
	}
}

func groupResource(g *authx.Group, members func() []authx.AuthUser) resource {
	return resource{
		scalar: groupGetter(g),
		multi: func(attr string) []elem {
			if strings.EqualFold(attr, "members") {
				out := []elem{}
				for _, m := range members() {
					out = append(out, elem{"value": toID(m.ID), "display": m.Email})
				}
				return out
			}
			return nil
		},
	}
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
	tkLBracket
	tkRBracket
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
		case c == '[':
			toks = append(toks, token{tkLBracket, "["})
			i++
		case c == ']':
			toks = append(toks, token{tkRBracket, "]"})
			i++
		case c == '"':
			var b strings.Builder
			j := i + 1
			for j < n && s[j] != '"' {
				if s[j] == '\\' && j+1 < n {
					// Only \" and \\ are escapes (RFC 7644 §3.4.2.2 / JSON). Any other backslash is
					// literal — keep it, rather than silently swallowing it and mangling the value.
					if nc := s[j+1]; nc == '"' || nc == '\\' {
						b.WriteByte(nc)
						j += 2
						continue
					}
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
			for j < n && s[j] != ' ' && s[j] != '\t' && s[j] != '(' && s[j] != ')' && s[j] != '[' && s[j] != ']' {
				j++
			}
			toks = append(toks, token{tkWord, s[i:j]})
			i = j
		}
	}
	return append(toks, token{tkEOF, ""}), nil
}

// --- recursive-descent parser: or < and < not < primary ---

// maxFilterDepth bounds nesting (parens / not / valuePath) so a pathologically nested filter can't
// overflow the stack (DoS). Every nested group re-enters parseOr, which enforces this.
const maxFilterDepth = 40

type parser struct {
	toks  []token
	pos   int
	depth int
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
	p.depth++
	if p.depth > maxFilterDepth {
		return nil, fmt.Errorf("filter nested too deeply")
	}
	defer func() { p.depth-- }()
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
		l, rr := left, right
		left = func(res resource) bool { return l(res) || rr(res) }
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
		l, rr := left, right
		left = func(res resource) bool { return l(res) && rr(res) }
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
		return func(res resource) bool { return !inner(res) }, nil
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
	attr := strings.ToLower(at.val)

	// valuePath: attr[ FILTER ] — matches if ANY sub-value of the multi-valued attr satisfies FILTER
	// (e.g. emails[type eq "work" and primary eq true], members[value eq "42"]).
	if p.peek().kind == tkLBracket {
		p.next()
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tkRBracket {
			return nil, fmt.Errorf("expected ']'")
		}
		p.next()
		return func(res resource) bool {
			for _, e := range res.multi(attr) {
				if inner(e.asResource()) {
					return true
				}
			}
			return false
		}, nil
	}

	opTok := p.next()
	if opTok.kind != tkWord {
		return nil, fmt.Errorf("expected an operator after %q", at.val)
	}
	op := strings.ToLower(opTok.val)
	if op == "pr" {
		return func(res resource) bool { v, ok := res.scalar(attr); return ok && v != "" }, nil
	}
	switch op {
	case "eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le":
	default:
		return nil, fmt.Errorf("unsupported operator %q", opTok.val)
	}
	vt := p.next()
	if vt.kind != tkWord && vt.kind != tkString {
		return nil, fmt.Errorf("expected a value after %q %q", at.val, opTok.val)
	}
	want := vt.val
	return func(res resource) bool {
		have, present := res.scalar(attr)
		return matchAttr(have, present, op, want)
	}, nil
}

// matchAttr applies a SCIM comparison operator. String attributes compare case-insensitively;
// gt/ge/lt/le are lexicographic (SCIM string ordering).
func matchAttr(have string, present bool, op, want string) bool {
	h, w := strings.ToLower(have), strings.ToLower(want)
	switch op {
	case "eq":
		return present && h == w
	case "ne":
		return present && h != w // an absent attribute doesn't satisfy `ne` (consistent with eq/co/…)
	case "co":
		return present && strings.Contains(h, w)
	case "sw":
		return present && strings.HasPrefix(h, w)
	case "ew":
		return present && strings.HasSuffix(h, w)
	case "gt":
		return present && h > w
	case "ge":
		return present && h >= w
	case "lt":
		return present && h < w
	case "le":
		return present && h <= w
	}
	return false
}
