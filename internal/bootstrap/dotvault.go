package bootstrap

import (
	"os"
	"path/filepath"
)

// dotvault serves a read-only SSH agent (goodtune/dotvault, internal/agent)
// over a per-user Unix socket on Linux/macOS and a named pipe on Windows.
// Its public Go client facade deliberately does not expose these endpoints —
// they are an internal deployment convention — and the agent speaks the
// standard SSH agent protocol, so gosh mirrors the small endpoint-resolution
// rule here instead of depending on the dotvault module. Keep this in sync
// with dotvault's paths.DefaultAgentSocket and config.DefaultAgentPipe.

// dotvaultAgentPipe is dotvault's default Windows named pipe for the agent.
const dotvaultAgentPipe = `\\.\pipe\dotvault-agent`

// dotvaultAgentSocket resolves dotvault's default agent socket path for a
// GOOS, mirroring dotvault's own resolution: the runtime dir
// ($XDG_RUNTIME_DIR/dotvault/agent.sock) when set, else the platform cache
// dir. Returns "" when the location cannot be determined.
func dotvaultAgentSocket(goos string, getenv func(string) string, home string) string {
	if rt := getenv("XDG_RUNTIME_DIR"); rt != "" {
		return filepath.Join(rt, "dotvault", "agent.sock")
	}
	switch goos {
	case "darwin":
		if home == "" {
			return ""
		}
		return filepath.Join(home, "Library", "Caches", "dotvault", "agent.sock")
	case "windows":
		// Windows dotvault serves a named pipe, not a socket.
		return ""
	default:
		if home == "" {
			return ""
		}
		return filepath.Join(home, ".cache", "dotvault", "agent.sock")
	}
}

func homeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}
