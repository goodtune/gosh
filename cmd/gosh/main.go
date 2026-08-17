// Command gosh is a mosh (mobile shell) client in pure Go: it bootstraps
// mosh-server over SSH, then speaks mosh's UDP State Synchronization Protocol
// directly, so one static binary serves every platform Go cross-compiles to —
// Windows included.
package main

import (
	"fmt"
	"os"
)

// version is the v-stripped semantic version, injected via
// -ldflags "-X main.version=...". Local builds without ldflags show "dev".
var version = "dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "gosh:", err)
		os.Exit(1)
	}
}
