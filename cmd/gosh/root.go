package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	osuser "os/user"
	"runtime"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/goodtune/gosh/internal/bootstrap"
	"github.com/goodtune/gosh/internal/client"
	"github.com/goodtune/gosh/internal/crypto"
	"github.com/goodtune/gosh/internal/termenv"
)

type rootOptions struct {
	sshPort    int
	udpPort    string
	server     string
	identity   string
	knownHosts string
	hostKey    string
	dotvault   string
}

func newRootCmd() *cobra.Command {
	opts := &rootOptions{}
	root := &cobra.Command{
		Use:   "gosh [user@]host [-- command...]",
		Short: "Mosh client in pure Go",
		Long: "gosh connects to a remote host with SSH, starts mosh-server, and then\n" +
			"runs the session over mosh's UDP protocol — surviving roaming and sleep.\n\n" +
			"Quit with Ctrl-^ followed by '.' (send a literal Ctrl-^ by doubling it).",
		Args:          cobra.MinimumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSession(cmd.Context(), opts, args[0], args[1:])
		},
	}
	root.Flags().IntVar(&opts.sshPort, "ssh-port", 22, "SSH port for the bootstrap connection")
	root.Flags().StringVarP(&opts.udpPort, "port", "p", "", "server-side UDP port or range (e.g. 60001 or 60000:61000)")
	root.Flags().StringVar(&opts.server, "server", "mosh-server", "path to mosh-server on the remote host")
	root.Flags().StringVarP(&opts.identity, "identity", "i", "", "SSH private key file (default: ssh-agent, then password prompt)")
	root.Flags().StringVar(&opts.knownHosts, "known-hosts", "", "known_hosts file (default ~/.ssh/known_hosts)")
	root.Flags().StringVar(&opts.hostKey, "host-key-policy", string(bootstrap.PolicyAcceptNew),
		"host key policy: strict, accept-new, or insecure")
	root.Flags().StringVar(&opts.dotvault, "dotvault-agent", bootstrap.DotvaultAuto,
		"dotvault SSH agent endpoint: auto (default location), off, or an explicit socket/pipe path")

	root.AddCommand(newVersionCmd(), newConnectCmd())
	root.CompletionOptions.DisableDefaultCmd = true
	return root
}

func splitTarget(target string) (user, host string) {
	if i := strings.LastIndex(target, "@"); i >= 0 {
		return target[:i], target[i+1:]
	}
	u := os.Getenv("USER")
	if u == "" {
		u = os.Getenv("USERNAME") // Windows
	}
	if u == "" {
		if cur, err := osuser.Current(); err == nil {
			u = cur.Username
			// Windows reports DOMAIN\user; the remote account is the bare name.
			if i := strings.LastIndexByte(u, '\\'); i >= 0 {
				u = u[i+1:]
			}
		}
	}
	return u, target
}

// authMethods assembles the SSH auth chain: explicit identity file, then
// ssh-agent, then an interactive password prompt when a TTY is available.
func authMethods(opts *rootOptions, user, host string) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if opts.identity != "" {
		pem, err := os.ReadFile(opts.identity)
		if err != nil {
			return nil, err
		}
		signer, err := ssh.ParsePrivateKey(pem)
		if err != nil {
			var pass *ssh.PassphraseMissingError
			if errors.As(err, &pass) && termenv.IsTerminal(os.Stdin) {
				fmt.Fprintf(os.Stderr, "Enter passphrase for %s: ", opts.identity)
				secret, rerr := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Fprintln(os.Stderr)
				if rerr != nil {
					return nil, rerr
				}
				signer, err = ssh.ParsePrivateKeyWithPassphrase(pem, secret)
			}
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", opts.identity, err)
			}
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if agent := bootstrap.AgentAuth(opts.dotvault); agent != nil {
		methods = append(methods, agent)
	}
	if termenv.IsTerminal(os.Stdin) {
		methods = append(methods, ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
			fmt.Fprintf(os.Stderr, "%s@%s's password: ", user, host)
			secret, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			return string(secret), err
		}), 3))
	}
	if len(methods) == 0 {
		return nil, errors.New("no SSH authentication available: no identity file, no ssh-agent, and no TTY for a password prompt")
	}
	return methods, nil
}

// knownHostsPathForPreference suppresses the host key algorithm preference
// when host key checking is off; see bootstrap.Options.KnownHostsPath.
func knownHostsPathForPreference(policy, path string) string {
	if bootstrap.HostKeyPolicy(policy) == bootstrap.PolicyInsecure {
		return ""
	}
	return path
}

func runSession(ctx context.Context, opts *rootOptions, target string, remoteCmd []string) error {
	user, host := splitTarget(target)

	// Resolve the default location here rather than leaving it to
	// HostKeyCallback, so the same file backs both the verification and the
	// host key algorithm preference derived from it. A failure to resolve is
	// not fatal at this point: passing "" lets HostKeyCallback resolve it and
	// report the error properly.
	knownHostsPath := opts.knownHosts
	if knownHostsPath == "" {
		if p, perr := bootstrap.DefaultKnownHostsPath(); perr == nil {
			knownHostsPath = p
		}
	}
	hostKeyCB, err := bootstrap.HostKeyCallback(bootstrap.HostKeyPolicy(opts.hostKey), knownHostsPath)
	if err != nil {
		return err
	}
	auth, err := authMethods(opts, user, host)
	if err != nil {
		return err
	}

	res, err := bootstrap.Run(bootstrap.Options{
		User:            user,
		Host:            host,
		SSHPort:         opts.sshPort,
		UDPPort:         opts.udpPort,
		ServerCommand:   opts.server,
		RemoteCommand:   remoteCmd,
		Auth:            auth,
		HostKeyCallback: hostKeyCB,
		// Left empty under the insecure policy: nothing is verified, so
		// there is no preference worth deriving and no reason to read the
		// file at all.
		KnownHostsPath: knownHostsPathForPreference(opts.hostKey, knownHostsPath),
	})
	if err != nil {
		return err
	}

	return runClient(ctx, res.Addr, res.Key)
}

// runClient attaches the local terminal to an established session.
func runClient(ctx context.Context, addr string, key crypto.Base64Key) error {
	// SIGTERM is never delivered on Windows (os.Interrupt covers Ctrl-C
	// there); listing it is harmless and gives Unix a clean-shutdown path.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	interactive := termenv.IsTerminal(os.Stdin) && termenv.IsTerminal(os.Stdout)
	var restore func()
	if interactive {
		state, err := termenv.MakeRaw(os.Stdin, os.Stdout)
		if err != nil {
			return fmt.Errorf("terminal raw mode: %w", err)
		}
		restore = func() { _ = state.Restore() }
		defer restore()
	}

	cfg := client.Config{
		Addr:          addr,
		Key:           key,
		Input:         os.Stdin,
		Output:        os.Stdout,
		Size:          func() (int, int) { return termenv.Size(os.Stdout) },
		DisableEscape: !interactive,
	}
	if interactive {
		cfg.Resized = client.WatchResize(ctx)
	}

	session, err := client.New(cfg)
	if err != nil {
		return err
	}
	err = session.Run(ctx)
	if restore != nil {
		restore()
		restore = func() {}
	}
	if err == nil || errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "\n[gosh is exiting.]")
		return nil
	}
	return err
}

func newConnectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connect host port",
		Short: "Attach to a running mosh-server directly (key from $MOSH_KEY)",
		Long: "connect skips the SSH bootstrap and dials an already-running mosh-server,\n" +
			"reading the session key from the MOSH_KEY environment variable — the same\n" +
			"contract as the reference mosh-client binary.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			keyStr := os.Getenv("MOSH_KEY")
			if keyStr == "" {
				return errors.New("MOSH_KEY environment variable is not set")
			}
			// Scrub the credential from our environment (and any children's)
			// for the session's lifetime, as reference mosh does.
			_ = os.Unsetenv("MOSH_KEY")
			key, err := crypto.ParseBase64Key(keyStr)
			if err != nil {
				return err
			}
			return runClient(cmd.Context(), net.JoinHostPort(args[0], args[1]), key)
		},
	}
	return cmd
}

func newVersionCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print build version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if jsonOut {
				fmt.Printf("{\"version\":%q,\"service\":\"gosh\",\"go_version\":%q,\"os\":%q,\"arch\":%q}\n",
					version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
				return nil
			}
			fmt.Println("gosh", version)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "machine-readable output")
	return cmd
}
