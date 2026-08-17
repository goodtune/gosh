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
	fd        int
	state     *term.State
	restoreVT func() // undoes the Windows console-mode change; nil elsewhere
}

// IsTerminal reports whether f is an interactive terminal.
func IsTerminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// MakeRaw puts stdin into raw mode and enables VT processing on stdout
// (Windows only; a no-op elsewhere). Returns a restore token.
func MakeRaw(stdin, stdout *os.File) (*State, error) {
	restoreVT, err := enableVT(stdout)
	if err != nil {
		return nil, err
	}
	st, err := term.MakeRaw(int(stdin.Fd()))
	if err != nil {
		if restoreVT != nil {
			restoreVT()
		}
		return nil, err
	}
	return &State{fd: int(stdin.Fd()), state: st, restoreVT: restoreVT}, nil
}

// Restore undoes MakeRaw, including the Windows console output mode.
func (s *State) Restore() error {
	if s == nil {
		return nil
	}
	var err error
	if s.state != nil {
		err = term.Restore(s.fd, s.state)
	}
	if s.restoreVT != nil {
		s.restoreVT()
	}
	return err
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

// TrySize is Size without the fallback: ok is false when the size cannot be
// determined, so pollers can skip the tick instead of reporting 80x24.
func TrySize(f *os.File) (width, height int, ok bool) {
	w, h, err := term.GetSize(int(f.Fd()))
	if err != nil || w <= 0 || h <= 0 {
		return 0, 0, false
	}
	return w, h, true
}
