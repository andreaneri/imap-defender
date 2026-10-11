package main

import "testing"

func TestAuthCommandScannerSimpleLogin(t *testing.T) {
    for _,size:=range []int{1,2,7,1024} {
        var s authCommandScanner
        input:=[]byte("A1 LOGIN \"alice\" \"secret\"\r\nB2 NOOP\r\nC3 LOGIN bob pass\r\n")
        var found []observedAuthCommand
        for i:=0;i<len(input);i+=size {
            end:=i+size;if end>len(input){end=len(input)}
            found=append(found,s.feed(input[i:end])...)
        }
        if s.disabled || len(found)!=2 || found[0].Tag!="A1" || found[1].Tag!="C3" {
            t.Fatalf("size=%d found=%v disabled=%v",size,found,s.disabled)
        }
    }
}
func TestAuthCommandScannerRejectsAmbiguous(t *testing.T) {
    for _,input:=range []string{
        "A LOGIN alice\r\n",
        "A LOGIN alice pass extra\r\n",
        "A LOGIN \"unterminated pass\r\n",
        "A LOGIN alice {4}\r\npass\r\n",
        "A AUTHENTICATE PLAIN\r\n",
    } {
        var s authCommandScanner
        found:=s.feed([]byte(input))
        if len(found)!=0 {t.Fatalf("unexpected candidate for %q",input)}
    }
}
func TestAuthCommandScannerLiteralFailOpen(t *testing.T) {
    var s authCommandScanner
    _=s.feed([]byte("A LOGIN {5}\r\n"))
    if !s.disabled {t.Fatal("literal did not disable scanner")}
    if len(s.feed([]byte("B LOGIN alice pass\r\n")))!=0 {t.Fatal("resumed after unsupported literal")}
}
func TestAuthCommandScannerClearsPasswordBuffer(t *testing.T) {
    var s authCommandScanner
    s.feed([]byte("A LOGIN alice secret\r\n"))
    if len(s.line)!=0 {t.Fatal("line retained")}
    for _,b:=range s.line[:cap(s.line)] {if b!=0 {t.Fatal("temporary buffer not cleared")}}
}

func TestAuthCommandScannerQuotedBracesAreNotLiterals(t *testing.T) {
    var s authCommandScanner
    commands:=s.feed([]byte("A LOGIN alice \"{123}\"\r\n"))
    if s.disabled || len(commands)!=1 || commands[0].Tag!="A" {
        t.Fatalf("quoted braces misclassified: disabled=%v commands=%v",s.disabled,commands)
    }
}

func TestAuthCommandScannerLiteralMarkerAfterSafeCommand(t *testing.T) {
    var s authCommandScanner
    commands:=s.feed([]byte("A LOGIN alice pass\r\nB LOGIN {4} pass\r\n"))
    if len(commands)!=0 || !s.disabled {
        t.Fatalf("partial batch should not publish candidates: %v disabled=%v",commands,s.disabled)
    }
}
