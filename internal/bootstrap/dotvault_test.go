package bootstrap

import (
	"path/filepath"
	"testing"
)

func TestDotvaultAgentSocket(t *testing.T) {
	env := func(vals map[string]string) func(string) string {
		return func(k string) string { return vals[k] }
	}
	cases := []struct {
		name string
		goos string
		env  map[string]string
		home string
		want string
	}{
		{
			name: "runtime dir wins on linux",
			goos: "linux",
			env:  map[string]string{"XDG_RUNTIME_DIR": "/run/user/1000"},
			home: "/home/g",
			want: filepath.Join("/run/user/1000", "dotvault", "agent.sock"),
		},
		{
			name: "linux cache fallback",
			goos: "linux",
			home: "/home/g",
			want: filepath.Join("/home/g", ".cache", "dotvault", "agent.sock"),
		},
		{
			name: "darwin cache fallback",
			goos: "darwin",
			home: "/Users/g",
			want: filepath.Join("/Users/g", "Library", "Caches", "dotvault", "agent.sock"),
		},
		{
			name: "runtime dir wins on darwin too",
			goos: "darwin",
			env:  map[string]string{"XDG_RUNTIME_DIR": "/tmp/rt"},
			home: "/Users/g",
			want: filepath.Join("/tmp/rt", "dotvault", "agent.sock"),
		},
		{
			name: "windows has no socket (named pipe instead)",
			goos: "windows",
			home: `C:\Users\g`,
			want: "",
		},
		{
			name: "no home, no runtime dir",
			goos: "linux",
			home: "",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dotvaultAgentSocket(tc.goos, env(tc.env), tc.home)
			if got != tc.want {
				t.Fatalf("dotvaultAgentSocket(%s) = %q, want %q", tc.goos, got, tc.want)
			}
		})
	}
}
