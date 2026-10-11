package main

import "bytes"

// authCommandScanner observes only complete, single-line LOGIN commands.
// It never retains a command or its credentials after the current line.
// AUTHENTICATE and literal-bearing LOGIN are deliberately unsupported:
// SASL challenges and IMAP literal continuations require bidirectional
// protocol state. Unsupported framing permanently disables classification.
// This component is inert and MUST NOT be used to delay the live relay.
type authCommandScanner struct {
    line []byte
    disabled bool
}

type observedAuthCommand struct {
    Tag string
    Method string
}

// feed returns only safely framed candidates. Its caller must additionally
// verify forwarding success before registering any tag for enforcement.
func (s *authCommandScanner) feed(chunk []byte) []observedAuthCommand {
    if s.disabled { return nil }
    var result []observedAuthCommand
    for _, b := range chunk {
        if len(s.line) >= maxPaceResponseLine {
            s.disable()
            return nil
        }
        s.line = append(s.line, b)
        if b != '\n' { continue }
        if len(s.line) < 2 || s.line[len(s.line)-2] != '\r' {
            s.disable()
            return nil
        }
        body := s.line[:len(s.line)-2]
        if bytes.IndexAny(body, "\r\n\x00") >= 0 {
            s.disable()
            return nil
        }
        tag, method, ok := scanSimpleLogin(body)
        if ok {
            result = append(result, observedAuthCommand{Tag:tag,Method:method})
        }
        // A command with any literal syntax cannot be safely tracked by
        // this deliberately narrow single-line parser. It must not scan
        // subsequent literal payload as though it were a command.
        if hasUnsupportedLiteralMarker(body) {
            s.disable()
            return nil
        }
        clear(s.line)
        s.line = s.line[:0]
    }
    return result
}

func (s *authCommandScanner) disable() {
    s.disabled = true
    clear(s.line)
    s.line = nil
}

// scanSimpleLogin verifies the presence of two IMAP astring arguments,
// with basic quoted escaping, without copying either argument.
func scanSimpleLogin(line []byte) (string,string,bool) {
    first := bytes.IndexByte(line,' ')
    if first <= 0 || first > maxObservedTag {return "","",false}
    tag := string(line[:first])
    if !validObservedTag(tag) {return "","",false}
    rest := line[first+1:]
    if !bytes.HasPrefix(rest,[]byte("LOGIN ")) {return "","",false}
    rest = rest[len("LOGIN "):]
    var ok bool
    rest,ok = skipLoginAstring(rest)
    if !ok || len(rest)==0 || rest[0]!=' ' {return "","",false}
    rest,ok = skipLoginAstring(rest[1:])
    if !ok || len(rest)!=0 {return "","",false}
    return tag,"LOGIN",true
}

func skipLoginAstring(p []byte) ([]byte,bool) {
    if len(p)==0 {return nil,false}
    if p[0]=='"' {
        escaped:=false
        for i:=1;i<len(p);i++ {
            b:=p[i]
            if escaped {
                if b!='"' && b!='\\' {return nil,false}
                escaped=false
                continue
            }
            if b=='\\' {escaped=true;continue}
            if b=='"' {return p[i+1:],true}
            if b<0x20 || b==0x7f {return nil,false}
        }
        return nil,false
    }
    i:=0
    for i<len(p) && p[i]!=' ' {
        b:=p[i]
        if b<=0x20 || b>=0x7f || bytes.IndexByte([]byte("(){%*\"\\]"),b)>=0 {
            return nil,false
        }
        i++
    }
    if i==0 {return nil,false}
    return p[i:],true
}

// hasUnsupportedLiteralMarker rejects only plausible IMAP literal markers,
// including non-synchronizing and binary literals. A brace in a quoted
// password is not a literal marker.
func hasUnsupportedLiteralMarker(body []byte) bool {
    quoted, escaped := false, false
    for i:=0;i<len(body);i++ {
        b:=body[i]
        if quoted {
            if escaped {escaped=false;continue}
            if b=='\\' {escaped=true;continue}
            if b=='"' {quoted=false}
            continue
        }
        if b=='"' {quoted=true;continue}
        if b=='{' && i+1<len(body) && body[i+1]>='0' && body[i+1]<='9' {
            return true
        }
    }
    return false
}
