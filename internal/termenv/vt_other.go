//go:build !windows

package termenv

import "os"

// enableVT is a no-op outside Windows: Unix terminals interpret VT sequences
// natively, so there is no mode to change or restore.
func enableVT(*os.File) (func(), error) { return nil, nil }
