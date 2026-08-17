// Package termenv wraps the local terminal plumbing the client needs: raw
// mode, size queries, and (on Windows) enabling VT escape-sequence
// processing so mosh's ANSI output renders in conhost and Windows Terminal.
package termenv

import (
	"os"

	"golang.org/x/term"
)

// State is an opaque restore token for Restore.
type State struct {
	fd    int
	state *term.State
}

// IsTerminal reports whether fd is an interactive terminal.
func IsTerminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// MakeRaw puts stdin into raw mode and enables VT processing on stdout
// (Windows only; a no-op elsewhere). Returns a restore token.
func MakeRaw(stdin, stdout *os.File) (*State, error) {
	if err := enableVT(stdout); err != nil {
		return nil, err
	}
	st, err := term.MakeRaw(int(stdin.Fd()))
	if err != nil {
		return nil, err
	}
	return &State{fd: int(stdin.Fd()), state: st}, nil
}

// Restore undoes MakeRaw.
func (s *State) Restore() error {
	if s == nil || s.state == nil {
		return nil
	}
	return term.Restore(s.fd, s.state)
}

// Size returns the terminal dimensions of f, defaulting to 80x24 when f is
// not a terminal (piped stdin in tests and scripts).
func Size(f *os.File) (width, height int) {
	w, h, err := term.GetSize(int(f.Fd()))
	if err != nil || w <= 0 || h <= 0 {
		return 80, 24
	}
	return w, h
}
