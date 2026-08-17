package bootstrap

import (
	"strings"
	"testing"
)

func TestConnectRegexp(t *testing.T) {
	out := "\r\nMOSH CONNECT 60001 zr0jtuYVKJnfJHP/XOOsbQ\r\n\nmosh-server (mosh 1.4.0)\n"
	m := connectRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatal("no match")
	}
	if m[1] != "60001" || m[2] != "zr0jtuYVKJnfJHP/XOOsbQ" {
		t.Fatalf("match = %q", m)
	}
	for _, bad := range []string{
		"MOSH CONNECT abc key",
		"MOSH CONNECT 60001 tooshortkey",
		"XMOSH CONNECT 60001 zr0jtuYVKJnfJHP/XOOsbQ",
	} {
		if connectRE.MatchString(bad) {
			t.Errorf("matched %q", bad)
		}
	}
}

func TestServerCommand(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("LANG", "en_AU.UTF-8")
	cmd := serverCommand(Options{})
	want := "TERM=xterm-256color mosh-server new -c 256 -l LANG=en_AU.UTF-8"
	if cmd != want {
		t.Fatalf("cmd = %q, want %q", cmd, want)
	}

	t.Setenv("LANG", "POSIX") // non-UTF-8 locale must be replaced
	cmd = serverCommand(Options{UDPPort: "60001", ServerCommand: "/usr/bin/mosh-server", RemoteCommand: []string{"tmux", "new -A"}})
	want = "TERM=xterm-256color /usr/bin/mosh-server new -c 256 -l LANG=C.UTF-8 -p 60001 -- tmux 'new -A'"
	if cmd != want {
		t.Fatalf("cmd = %q, want %q", cmd, want)
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"plain":       "plain",
		"":            "''",
		"two words":   "'two words'",
		"it's":        `'it'\''s'`,
		"a$b":         "'a$b'",
		"semi;colon":  "'semi;colon'",
		"back`tick":   "'back`tick'",
		"redirect>me": "'redirect>me'",
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRunValidation(t *testing.T) {
	if _, err := Run(Options{}); err == nil || !strings.Contains(err.Error(), "host") {
		t.Fatalf("err = %v", err)
	}
	if _, err := Run(Options{Host: "example.com"}); err == nil || !strings.Contains(err.Error(), "host key") {
		t.Fatalf("err = %v", err)
	}
}
