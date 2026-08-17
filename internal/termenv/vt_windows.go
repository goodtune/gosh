//go:build windows

package termenv

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableVT switches the console output handle into VT processing mode so ANSI
// escape sequences from the server render instead of printing literally.
// Failure is ignored when stdout is not a console (redirected output).
func enableVT(stdout *os.File) error {
	handle := windows.Handle(stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return nil // not a console
	}
	mode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING | windows.DISABLE_NEWLINE_AUTO_RETURN
	if err := windows.SetConsoleMode(handle, mode); err != nil {
		// DISABLE_NEWLINE_AUTO_RETURN is unsupported on older builds; retry
		// with just VT processing before giving up.
		mode &^= windows.DISABLE_NEWLINE_AUTO_RETURN
		return windows.SetConsoleMode(handle, mode)
	}
	return nil
}
