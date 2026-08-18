// Package bootstrap starts mosh-server on a remote host over SSH and parses
// the MOSH CONNECT response, mirroring what the mosh wrapper script does with
// the system ssh binary — but with golang.org/x/crypto/ssh so the client
// cross-compiles (Windows included) with no external dependencies.
package bootstrap

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/goodtune/gosh/internal/crypto"
)

// Options configures the SSH bootstrap.
type Options struct {
	User    string
	Host    string
	SSHPort int // default 22

	// UDPPort optionally requests a fixed server port ("-p N" or "-p LO:HI").
	UDPPort string

	// ServerCommand is the remote mosh-server binary (default "mosh-server").
	ServerCommand string

	// RemoteCommand, when non-empty, is passed to mosh-server after "--" so
	// the server runs it instead of the login shell.
	RemoteCommand []string

	// Term is the TERM to advertise to the remote (default: $TERM, then
	// "xterm-256color").
	Term string

	// Auth methods, tried in order. Defaults to ssh-agent + prompts wired by
	// the CLI; tests inject password auth directly.
	Auth []ssh.AuthMethod

	// HostKeyCallback validates the server host key. Required.
	HostKeyCallback ssh.HostKeyCallback

	// KnownHostsPath, when set, is read to prefer the host key algorithms
	// already recorded there for this host, the way OpenSSH does — otherwise
	// a host known under one algorithm can fail to verify because the server
	// was asked for a different one (see knownHostKeyAlgorithms). Preference
	// only: nothing becomes unnegotiable, so leaving it empty is safe and
	// merely forgoes the reordering. Note the asymmetry with HostKeyCallback's
	// path argument, which does read the default location when empty: here
	// empty means "derive nothing", so a caller that never named a file never
	// has one read behind its back. Pass DefaultKnownHostsPath explicitly to
	// get the usual location.
	KnownHostsPath string

	// Timeout bounds the TCP connect (default 10s).
	Timeout time.Duration
}

// Result is the parsed bootstrap outcome.
type Result struct {
	// Addr is the "host:port" UDP address to dial: the IP actually used for
	// the SSH connection plus the port mosh-server printed.
	Addr string
	// Port is the UDP port mosh-server printed.
	Port int
	// Key is the parsed session key.
	Key crypto.Base64Key
	// ServerOutput is everything mosh-server printed (for -v diagnostics).
	ServerOutput string
}

var connectRE = regexp.MustCompile(`(?m)^MOSH CONNECT (\d{1,5}) ([A-Za-z0-9/+]{22})\s*$`)

// Sentinel values for the dotvault-agent setting accepted by AgentAuth.
const (
	// DotvaultAuto resolves dotvault's default agent endpoint for the
	// platform ($XDG_RUNTIME_DIR/dotvault/agent.sock or the cache-dir
	// fallback on Unix; the \\.\pipe\dotvault-agent named pipe on Windows).
	DotvaultAuto = "auto"
	// DotvaultOff skips the dotvault agent entirely.
	DotvaultOff = "off"
)

// AgentAuth returns an ssh.AuthMethod aggregating the identities of every
// reachable ssh-agent, or nil if none is. The chain is SSH_AUTH_SOCK, then
// the dotvault agent when available (socket on Unix, named pipe on Windows;
// dotvault selects the endpoint — DotvaultAuto, DotvaultOff, or an explicit
// path), then Windows' native OpenSSH agent pipe. Signers are offered in
// that order; the SSH handshake stops at the first key the server accepts.
func AgentAuth(dotvault string) ssh.AuthMethod {
	callback := agentSigners(dotvault)
	if callback == nil {
		return nil
	}
	return ssh.PublicKeysCallback(callback)
}

// agentSigners is AgentAuth's engine, separated so tests can inspect the
// aggregated signer list without driving a full SSH handshake.
func agentSigners(dotvault string) func() ([]ssh.Signer, error) {
	conns := dialAgents(dotvault)
	if len(conns) == 0 {
		return nil
	}
	clients := make([]agent.ExtendedAgent, len(conns))
	for i, conn := range conns {
		clients[i] = agent.NewClient(conn)
	}
	return func() ([]ssh.Signer, error) {
		var signers []ssh.Signer
		for _, cl := range clients {
			s, err := cl.Signers()
			if err != nil {
				continue // one dead agent must not blank the others
			}
			signers = append(signers, s...)
		}
		return signers, nil
	}
}

// Run connects over SSH, launches mosh-server, and returns the session
// parameters. The SSH connection is closed before returning — mosh-server
// has detached by then, exactly like the reference implementation.
func Run(opts Options) (*Result, error) {
	if opts.Host == "" {
		return nil, errors.New("bootstrap: host is required")
	}
	if opts.HostKeyCallback == nil {
		return nil, errors.New("bootstrap: host key callback is required")
	}
	port := opts.SSHPort
	if port == 0 {
		port = 22
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	addr := net.JoinHostPort(opts.Host, strconv.Itoa(port))
	cfg := &ssh.ClientConfig{
		User:            opts.User,
		Auth:            opts.Auth,
		HostKeyCallback: opts.HostKeyCallback,
		// Derived here rather than by the caller so it uses the same addr
		// the dial does, port default included.
		HostKeyAlgorithms: knownHostKeyAlgorithms(opts.KnownHostsPath, addr),
		Timeout:           timeout,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("ssh %s: %w", addr, err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	out, err := session.CombinedOutput(serverCommand(opts))
	output := string(out)
	if err != nil {
		return nil, fmt.Errorf("mosh-server failed: %w\n%s", err, strings.TrimSpace(RedactKeys(output)))
	}

	m := connectRE.FindStringSubmatch(output)
	if m == nil {
		return nil, fmt.Errorf("bootstrap: no MOSH CONNECT line in server output:\n%s", strings.TrimSpace(RedactKeys(output)))
	}
	udpPort, err := strconv.Atoi(m[1])
	if err != nil || udpPort < 1 || udpPort > 65535 {
		return nil, fmt.Errorf("bootstrap: invalid MOSH CONNECT port %q", m[1])
	}
	key, err := crypto.ParseBase64Key(m[2])
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}

	// Reuse the address family and IP that carried the SSH connection so a
	// multi-homed or DNS-round-robin host gets the same instance.
	host, _, err := net.SplitHostPort(client.Conn.RemoteAddr().String())
	if err != nil {
		host = opts.Host
	}

	return &Result{
		Addr:         net.JoinHostPort(host, strconv.Itoa(udpPort)),
		Port:         udpPort,
		Key:          key,
		ServerOutput: RedactKeys(output),
	}, nil
}

// RedactKeys blanks the session key out of MOSH CONNECT lines so server
// output can be surfaced in errors and diagnostics without leaking the
// credential into terminals or logs.
func RedactKeys(output string) string {
	return connectRE.ReplaceAllString(output, "MOSH CONNECT $1 <key redacted>")
}

// serverCommand builds the remote command line. The TERM/LANG environment
// rides as env assignments ahead of the command — sshd runs exec requests
// through the login shell, so plain VAR=value prefixes are honoured — because
// sshd's AcceptEnv rarely admits arbitrary SendEnv values.
func serverCommand(opts Options) string {
	server := opts.ServerCommand
	if server == "" {
		server = "mosh-server"
	}
	term := opts.Term
	if term == "" {
		term = os.Getenv("TERM")
	}
	if term == "" {
		term = "xterm-256color"
	}
	lang := os.Getenv("LANG")
	if !strings.Contains(strings.ToUpper(lang), "UTF-8") && !strings.Contains(strings.ToUpper(lang), "UTF8") {
		lang = "C.UTF-8"
	}

	parts := []string{
		"TERM=" + shellQuote(term),
		server, "new", "-c", "256",
		"-l", shellQuote("LANG=" + lang),
	}
	if opts.UDPPort != "" {
		parts = append(parts, "-p", shellQuote(opts.UDPPort))
	}
	if len(opts.RemoteCommand) > 0 {
		parts = append(parts, "--")
		for _, a := range opts.RemoteCommand {
			parts = append(parts, shellQuote(a))
		}
	}
	return strings.Join(parts, " ")
}

// shellQuote single-quotes a string for POSIX sh, the shell sshd hands exec
// requests to.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	// '=' is deliberately not here: a bare VAR=value argument is inert in
	// argument position, and the TERM= prefix relies on staying unquoted.
	if !strings.ContainsAny(s, " \t\n\"'\\$`!*?[]{}();<>|&~#") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
