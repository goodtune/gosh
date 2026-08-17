//go:build windows

package termenv

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableVT switches the console output handle into VT processing mode so ANSI
// escape sequences from the server render instead of printing literally. The
// returned func restores the original mode; it is nil when stdout is not a
// console (redirected output), where there is nothing to change.
func enableVT(stdout *os.File) (func(), error) {
	handle := windows.Handle(stdout.Fd())
	var orig uint32
	if err := windows.GetConsoleMode(handle, &orig); err != nil {
		return nil, nil // not a console
	}
	restore := func() { _ = windows.SetConsoleMode(handle, orig) }
	mode := orig | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING | windows.DISABLE_NEWLINE_AUTO_RETURN
	if err := windows.SetConsoleMode(handle, mode); err != nil {
		// DISABLE_NEWLINE_AUTO_RETURN is unsupported on older builds; retry
		// with just VT processing before giving up.
		mode &^= windows.DISABLE_NEWLINE_AUTO_RETURN
		if err := windows.SetConsoleMode(handle, mode); err != nil {
			return nil, err
		}
	}
	return restore, nil
}
