package main

import (
	"strings"
	"unicode/utf8"
)

const maxObservedIdentity = 1024
const maxObservedSASLResponse = 65536

// authIdentity retains identities only. LOGIN's second argument and the
// password portion of PLAIN are never copied into observer-owned storage.
type authIdentity struct {
	method    string
	mechanism []byte
	mode      int
	name      []byte
	escaped   bool
	known     bool
	invalid   bool
	plain     plainIdentity
}

const (
	identityStart = iota
	identityAtom
	identityQuoted
	identityMarker
	identityLiteral
	identityTilde
	identityDone
)

func validIdentity(p []byte) bool {
	if len(p) == 0 || !utf8.Valid(p) {
		return false
	}
	for _, b := range p {
		if b < 0x20 || b == 0x7f {
			return false
		}
	}
	return true
}

func (a *authIdentity) appendName(b byte) {
	if a.invalid {
		return
	}
	if len(a.name) >= maxObservedIdentity {
		a.invalid = true
		clear(a.name)
		a.name = nil
		return
	}
	a.name = append(a.name, b)
}

func (a *authIdentity) completeName() {
	a.mode = identityDone
	a.known = !a.invalid && validIdentity(a.name)
	if !a.known {
		clear(a.name)
		a.name = nil
	}
}

func (a *authIdentity) consume(b byte) {
	if a.method == "AUTHENTICATE" {
		a.consumeSASL(b)
		return
	}
	switch a.mode {
	case identityStart:
		switch b {
		case ' ':
			return
		case '"':
			a.mode = identityQuoted
		case '{':
			a.mode = identityMarker
		case '~':
			a.mode = identityTilde
		default:
			a.mode = identityAtom
			a.appendName(b)
		}
	case identityTilde:
		if b == '{' {
			a.mode = identityMarker
			return
		}
		a.mode = identityAtom
		a.appendName('~')
		a.consume(b)
	case identityAtom:
		if b == ' ' {
			a.completeName()
		} else {
			if strings.ContainsRune("(){%*\"\\", rune(b)) {
				a.invalid = true
			}
			a.appendName(b)
		}
	case identityQuoted:
		if a.escaped {
			if b != '"' && b != '\\' {
				a.invalid = true
			}
			a.appendName(b)
			a.escaped = false
		} else if b == '\\' {
			a.escaped = true
		} else if b == '"' {
			a.completeName()
		} else {
			a.appendName(b)
		}
		// Marker digits and every byte after the username are intentionally ignored.
	}
}

func (a *authIdentity) literalByte(b byte, remaining uint64) {
	if a.method != "LOGIN" || a.mode != identityLiteral {
		return
	}
	a.appendName(b)
	if remaining == 0 {
		a.completeName()
	}
}

func (a *authIdentity) endLine(literal bool, length uint64) {
	if a.method == "AUTHENTICATE" {
		if a.mode == identityStart {
			a.finishMechanism()
			return
		}
		if a.mode == identityAtom {
			a.plain.finish()
			a.mode = identityDone
		}
		return
	}
	switch a.mode {
	case identityTilde:
		a.appendName('~')
		a.completeName()
	case identityAtom:
		a.completeName()
	case identityMarker:
		if !literal {
			a.invalid = true
			a.completeName()
			return
		}
		a.mode = identityLiteral
		if length > maxObservedIdentity {
			a.invalid = true
		}
		if length == 0 {
			a.completeName()
		}
	}
}

func (a *authIdentity) finishMechanism() {
	mechanism := strings.ToUpper(string(a.mechanism))
	if mechanism == "PLAIN" || mechanism == "LOGIN" {
		a.plain = plainIdentity{login: mechanism == "LOGIN"}
	} else {
		a.invalid = true
	}
	a.mode = identityAtom
}

func (a *authIdentity) consumeSASL(b byte) {
	if a.mode == identityStart {
		if b == ' ' {
			a.finishMechanism()
			return
		}
		if len(a.mechanism) >= 32 || !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_') {
			a.invalid = true
			return
		}
		a.mechanism = append(a.mechanism, b)
		return
	}
	if a.mode == identityAtom && !a.invalid {
		a.plain.consume(b)
	}
}

func (a *authIdentity) result(outcome string) authResult {
	r := authResult{Method: a.method, Outcome: outcome}
	if a.method == "LOGIN" && a.known {
		r.Username = string(a.name)
		r.UsernameKnown = true
	}
	if a.method == "AUTHENTICATE" {
		r.Mechanism = strings.ToUpper(string(a.mechanism))
		if !a.invalid && a.plain.known {
			r.Username = string(a.plain.authcid)
			r.UsernameKnown = true
			r.AuthorizationID = string(a.plain.authzid)
		}
	}
	return r
}

// The Base64 decoder stops accumulating decoded bits after the second NUL.
// Remaining password bytes are counted structurally, never decoded or stored.
type plainIdentity struct {
	login                bool
	authcid, authzid     []byte
	chars, padding       int
	acc                  uint32
	bits                 uint
	separators           int
	decoded, prefixBytes int
	invalid, known       bool
}

func base64Value(b byte) (uint32, bool) {
	switch {
	case b >= 'A' && b <= 'Z':
		return uint32(b - 'A'), true
	case b >= 'a' && b <= 'z':
		return uint32(b - 'a' + 26), true
	case b >= '0' && b <= '9':
		return uint32(b - '0' + 52), true
	case b == '+':
		return 62, true
	case b == '/':
		return 63, true
	}
	return 0, false
}

func (p *plainIdentity) consume(b byte) {
	if p.invalid {
		return
	}
	pos := p.chars % 4
	p.chars++
	if p.chars > maxObservedSASLResponse {
		p.reject()
		return
	}
	if b == '=' {
		if pos < 2 || p.padding >= 2 {
			p.reject()
			return
		}
		p.padding++
		return
	}
	v, ok := base64Value(b)
	if !ok || p.padding != 0 {
		p.reject()
		return
	}
	// Count decoded bytes even after identity extraction, without decoding secrets.
	if pos != 0 {
		p.decoded++
	}
	if !p.login && p.separators == 2 {
		return
	}
	p.acc = p.acc<<6 | v
	p.bits += 6
	if p.bits >= 8 {
		p.bits -= 8
		decoded := byte(p.acc >> p.bits)
		p.acc &= (1 << p.bits) - 1
		if !p.login && decoded == 0 {
			p.separators++
			if p.separators == 2 {
				p.prefixBytes = p.decoded
				p.acc = 0
				p.bits = 0
			}
			return
		}
		target := &p.authzid
		if p.login || p.separators == 1 {
			target = &p.authcid
		}
		if len(*target) >= maxObservedIdentity {
			p.reject()
			return
		}
		*target = append(*target, decoded)
	}
}

func (p *plainIdentity) reject() {
	p.invalid = true
	p.known = false
	clear(p.authcid)
	clear(p.authzid)
	p.authcid = nil
	p.authzid = nil
	p.acc = 0
	p.bits = 0
}

func (p *plainIdentity) finish() {
	if p.invalid || p.chars == 0 || p.chars%4 != 0 || (!p.login && (p.separators != 2 || p.decoded <= p.prefixBytes)) || !validIdentity(p.authcid) || len(p.authzid) > 0 && !validIdentity(p.authzid) {
		p.reject()
		return
	}
	p.known = true
}
