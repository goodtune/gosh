//go:build !windows

package termenv

import "os"

// enableVT is a no-op outside Windows: Unix terminals interpret VT sequences
// natively.
func enableVT(*os.File) error { return nil }
