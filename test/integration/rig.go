//go:build integration

package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/ssh"

	"github.com/goodtune/gosh/internal/bootstrap"
)

// Credentials for the containerised rig; the external rig supplies its own
// through the environment.
const (
	dockerSSHUser     = "gosh"
	dockerSSHPassword = "gosh-integration"
)

// udpPorts are the fixed container-side ports each test asks mosh-server to
// bind, one per test so sessions never collide.
var udpPorts = []string{"60001", "60002", "60003"}

// rig is a reachable sshd with mosh-server installed. It is either a
// container this package starts (the default, and what `make
// integration-test` uses) or a server the caller already started and
// described through GOSH_IT_* — the shape CI uses on macOS (Homebrew mosh
// plus a throwaway sshd) and on Windows (mosh inside WSL), where Docker
// cannot host a Linux container.
type rig struct {
	sshHost string
	sshPort int
	user    string
	auth    []ssh.AuthMethod

	// serverCommand overrides the remote mosh-server binary. Homebrew installs
	// it outside the PATH sshd hands a non-interactive command, so the macOS
	// job names it absolutely rather than relying on shell startup files.
	serverCommand string

	// udpHostPort maps a container-side UDP port to the port reachable from
	// the test process. They differ only under Docker's port mapping.
	udpHostPort map[string]int
	// close releases the rig; nil for an externally managed one.
	close func()
}

var (
	rigOnce sync.Once
	rigVal  *rig
	rigErr  error
)

// startRig returns the shared rig, starting it on first use.
func startRig(t *testing.T) *rig {
	t.Helper()
	rigOnce.Do(func() {
		if externallyManaged() {
			rigVal, rigErr = externalRig()
			return
		}
		rigVal, rigErr = dockerRig()
	})
	if rigErr != nil {
		t.Fatalf("start rig: %v", rigErr)
	}
	return rigVal
}

// externallyManaged reports whether the caller pointed the suite at an sshd
// it started itself.
func externallyManaged() bool { return os.Getenv("GOSH_IT_SSH_PORT") != "" }

// externalRig describes an sshd the workflow (or a developer) already
// started. mosh-server binds the requested UDP port on that same host, so no
// port translation is involved.
func externalRig() (*rig, error) {
	host := os.Getenv("GOSH_IT_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	port, err := strconv.Atoi(os.Getenv("GOSH_IT_SSH_PORT"))
	if err != nil {
		return nil, fmt.Errorf("GOSH_IT_SSH_PORT: %w", err)
	}
	user := os.Getenv("GOSH_IT_USER")
	if user == "" {
		return nil, fmt.Errorf("GOSH_IT_USER must be set alongside GOSH_IT_SSH_PORT")
	}

	auth, err := externalAuth()
	if err != nil {
		return nil, err
	}

	r := &rig{
		sshHost:       host,
		sshPort:       port,
		user:          user,
		auth:          auth,
		serverCommand: os.Getenv("GOSH_IT_SERVER_COMMAND"),
		udpHostPort:   map[string]int{},
	}
	for _, p := range udpPorts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, err
		}
		r.udpHostPort[p] = n
	}
	if err := waitForTCP(net.JoinHostPort(host, strconv.Itoa(port)), 2*time.Minute); err != nil {
		return nil, err
	}
	return r, nil
}

// externalAuth builds the SSH auth methods for an external rig: a private key
// when GOSH_IT_KEY names one (what CI uses — neither the macOS runner user
// nor the WSL user has a usable password), otherwise GOSH_IT_PASSWORD.
func externalAuth() ([]ssh.AuthMethod, error) {
	if keyPath := os.Getenv("GOSH_IT_KEY"); keyPath != "" {
		pem, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read GOSH_IT_KEY: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(pem)
		if err != nil {
			return nil, fmt.Errorf("parse GOSH_IT_KEY: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	}
	if password := os.Getenv("GOSH_IT_PASSWORD"); password != "" {
		return []ssh.AuthMethod{ssh.Password(password)}, nil
	}
	return nil, fmt.Errorf("set GOSH_IT_KEY or GOSH_IT_PASSWORD for the external rig")
}

// waitForTCP blocks until the address accepts a connection. An externally
// managed sshd is started by a preceding workflow step that does not
// necessarily wait for the listener.
func waitForTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("sshd at %s never accepted a connection: %w", addr, lastErr)
}

// dockerRig builds and starts the Debian sshd+mosh-server image: one sshd,
// multiple mosh-server sessions on distinct fixed UDP ports.
func dockerRig() (*rig, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	exposed := []string{"22/tcp"}
	for _, p := range udpPorts {
		exposed = append(exposed, p+"/udp")
	}
	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context: "testdata",
		},
		ExposedPorts: exposed,
		WaitingFor:   wait.ForListeningPort("22/tcp").WithStartupTimeout(2 * time.Minute),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}
	// Past this point the container is running but not yet reachable through
	// a rig, so nothing else can stop it: tear it down on any error rather
	// than leaving it for Ryuk.
	defer func() {
		if err != nil {
			_ = container.Terminate(context.Background())
		}
	}()

	r := &rig{
		sshHost:     "127.0.0.1",
		user:        dockerSSHUser,
		auth:        []ssh.AuthMethod{ssh.Password(dockerSSHPassword)},
		udpHostPort: map[string]int{},
		close:       func() { _ = container.Terminate(context.Background()) },
	}
	// Assign through the function's err so the deferred teardown above sees a
	// failure; a fresh `:=` inside the loop would shadow it.
	mappedPort := func(port string) (int, error) {
		mapped, err := container.MappedPort(ctx, port)
		if err != nil {
			return 0, err
		}
		return int(mapped.Num()), nil
	}
	if r.sshPort, err = mappedPort("22/tcp"); err != nil {
		return nil, err
	}
	for _, p := range udpPorts {
		var hostPort int
		if hostPort, err = mappedPort(p + "/udp"); err != nil {
			return nil, err
		}
		r.udpHostPort[p] = hostPort
	}
	return r, nil
}

// bootstrapSession launches mosh-server on the given server-side UDP port and
// returns the address the test process must dial plus the session key.
func bootstrapSession(t *testing.T, r *rig, serverPort string) (addr string, res *bootstrap.Result) {
	t.Helper()
	res, err := bootstrap.Run(bootstrap.Options{
		User:            r.user,
		Host:            r.sshHost,
		SSHPort:         r.sshPort,
		UDPPort:         serverPort,
		ServerCommand:   r.serverCommand,
		Term:            "xterm-256color",
		Auth:            r.auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	want, err := strconv.Atoi(serverPort)
	if err != nil {
		t.Fatal(err)
	}
	if res.Port != want {
		t.Fatalf("mosh-server bound port %d, requested %s", res.Port, serverPort)
	}
	// Under Docker the port mosh-server printed is container-internal; dial
	// the mapping instead.
	hostPort, ok := r.udpHostPort[serverPort]
	if !ok {
		t.Fatalf("no reachable mapping for UDP port %s", serverPort)
	}
	return net.JoinHostPort(r.sshHost, strconv.Itoa(hostPort)), res
}
