<p align="center">
  <img src="https://raw.githubusercontent.com/goodtune/gosh/main/assets/gosh-wordmark.png" alt="gosh" width="460">
</p>

<p align="center">
  A <a href="https://mosh.org">mosh</a> (mobile shell) client written in pure Go —
  <strong>Windows</strong>, macOS, and Linux from one static binary.
</p>

gosh speaks the mosh protocol — SSH bootstrap, then AES-128-OCB3-sealed UDP datagrams carrying mosh's State Synchronization Protocol — with no cgo and no system dependencies (not even an ssh binary), so a single static binary cross-compiles to every platform Go supports, **including Windows**, where the reference mosh client has never shipped natively.

## Platforms

<img src="https://raw.githubusercontent.com/goodtune/gosh/main/assets/gosh-icon-128.png" alt="" width="96" align="right">

| OS | Release targets | Unit tests in CI | End-to-end against a real `mosh-server` |
| --- | --- | --- | --- |
| **Windows** | amd64, arm64 | ✅ `windows-latest` | ✅ native `gosh.exe` against `mosh-server` running in WSL |
| **macOS** | amd64, arm64 | ✅ `macos-latest` | ✅ Homebrew `mosh-server` behind a throwaway sshd |
| **Linux** | amd64, arm64 | ✅ `ubuntu-latest` | ✅ Debian sshd + `mosh-server` container (testcontainers) |

Windows is the primary target: no ssh binary, no Cygwin, no WSL needed to *run* gosh — WSL appears above only because CI has to put a POSIX `mosh-server` somewhere for the Windows client to talk to. Every job runs on its runner's own architecture (arm64 on macOS, amd64 elsewhere); the other architectures are cross-compiled and not executed.

Every build is `CGO_ENABLED=0`, so the same source cross-compiles to any other platform Go supports with nothing but `GOOS`/`GOARCH`.

## Usage

```sh
gosh user@host                 # connect, run your login shell
gosh user@host -- tmux new -A  # run a command instead of the shell
gosh -i ~/.ssh/id_ed25519 user@host
gosh -p 60001 user@host        # request a fixed server UDP port
```

Quit with `Ctrl-^` then `.` (send a literal `Ctrl-^` by pressing it twice); escape processing is disabled when stdin is not a TTY, so piped sessions pass bytes through untouched. The session survives roaming between networks, laptop sleep, and flaky links — that's the point of mosh. Sends and (re)dials are time-bounded, so a blip can't freeze the client itself, only delay it; the client also recovers from a route that silently stops delivering without ever erroring (which is what a Wi-Fi/Ethernet switch or sleep/resume can leave behind, especially on Windows) by re-homing to a fresh local port after 10 seconds with no confirmed round trip, the same way the reference mosh client does.

SSH authentication tries, in order: an explicit `-i` identity file, every reachable ssh-agent, and an interactive password prompt. The agent chain covers `SSH_AUTH_SOCK`, a running [dotvault](https://github.com/goodtune/dotvault) daemon's SSH agent when present (`$XDG_RUNTIME_DIR/dotvault/agent.sock` or the cache-dir fallback on Linux/macOS, the `\\.\pipe\dotvault-agent` named pipe on Windows — tune with `--dotvault-agent auto|off|<path>`), and Windows' native OpenSSH agent pipe; identities from all of them are offered together. Note the usual agent trade-off: every offered public key (including principals embedded in dotvault-minted certificates) is disclosed to the server you connect to — use `--dotvault-agent off` if that matters for a given host. Host keys verify against `~/.ssh/known_hosts` with `accept-new` semantics by default (`--host-key-policy strict|accept-new|insecure`). As OpenSSH does, gosh prefers the host key algorithms already recorded for a host, so a host you know by only one key type verifies against that type instead of failing over whichever type gosh would otherwise ask for first.

`gosh connect <ip> <port>` attaches directly to a running mosh-server, reading the session key from `$MOSH_KEY` — the same contract as the reference `mosh-client` binary.

The remote host needs `mosh-server` installed (it's in every distro's `mosh` package) and UDP reachability on the negotiated port (60000–61000 by default).

## How it works

1. **Bootstrap** — gosh connects over SSH (`golang.org/x/crypto/ssh`, no system ssh binary needed) and runs `mosh-server new`, parsing the `MOSH CONNECT <port> <key>` reply. The SSH connection then closes; it is not used again.
2. **Datagram layer** — every UDP datagram is sealed with AES-128 OCB3 (RFC 7253, implemented in-tree against the RFC test vectors) under the session key, with a direction-and-sequence nonce and 16-bit timestamp echoes for RTT estimation.
3. **State sync** — keystrokes and window resizes are synchronized to the server as diffs of a `UserStream`; the server sends back diffs of its terminal state, which gosh applies to your terminal. Loss and reordering are handled by acknowledgment-driven retransmission, not replay — the protocol synchronizes state, it does not stream bytes.

## Building

```sh
make build          # bin/gosh for the current platform
make build-all      # linux/darwin/windows × amd64/arm64
make test           # unit tests (includes RFC 7253 OCB vectors)
make integration-test  # end-to-end against a real sshd+mosh-server container (needs Docker)
```

`make integration-test` builds and starts that container itself. Point the same suite at an sshd you already have — a VM, a remote box, or a local `mosh-server` where Docker is not an option, which is how the macOS and Windows CI jobs reach a server — by setting `GOSH_IT_SSH_PORT` (this selects the external rig) along with `GOSH_IT_HOST`, `GOSH_IT_USER`, either `GOSH_IT_KEY` (private key file) or `GOSH_IT_PASSWORD`, and optionally `GOSH_IT_SERVER_COMMAND` when `mosh-server` is not on the PATH sshd hands a non-interactive command. The host must let the suite bind UDP 60001 and 60002.

## Status

Interactive sessions, roaming, remote commands, resize, and clean shutdown are implemented and exercised end-to-end in CI against the reference `mosh-server`. Not yet implemented: predictive local echo (mosh's speculative rendering), IP roaming notifications in the status line, and the `MOSH_ESCAPE_KEY` override.

## Branding

The gosh artwork lives in [`assets/`](assets): `gosh-wordmark.png` (logo with text), `gosh-primary.png` (the mark on its own, 1254×1254), `gosh-icon-{512,128,64}.png` for application icons, and `gosh-favicon-{32,16}.png` for the web. All are RGBA with transparent backgrounds, so they sit on light or dark surfaces unchanged.

<p align="center">
  <img src="https://raw.githubusercontent.com/goodtune/gosh/main/assets/gosh-icon-128.png" alt="gosh icon, 128px" width="128">
  <img src="https://raw.githubusercontent.com/goodtune/gosh/main/assets/gosh-icon-64.png" alt="gosh icon, 64px" width="64">
  <img src="https://raw.githubusercontent.com/goodtune/gosh/main/assets/gosh-favicon-32.png" alt="gosh favicon, 32px" width="32">
  <img src="https://raw.githubusercontent.com/goodtune/gosh/main/assets/gosh-favicon-16.png" alt="gosh favicon, 16px" width="16">
</p>

## License

MIT
