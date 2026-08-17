# gosh

A [mosh](https://mosh.org) (mobile shell) client written in pure Go.

gosh speaks the mosh protocol — SSH bootstrap, then AES-128-OCB3-sealed UDP datagrams carrying mosh's State Synchronization Protocol — with no cgo and no system dependencies (not even an ssh binary), so a single static binary cross-compiles to every platform Go supports, **including Windows**, where the reference mosh client has never shipped natively.

## Usage

```sh
gosh user@host                 # connect, run your login shell
gosh user@host -- tmux new -A  # run a command instead of the shell
gosh -i ~/.ssh/id_ed25519 user@host
gosh -p 60001 user@host        # request a fixed server UDP port
```

Quit with `Ctrl-^` then `.` (send a literal `Ctrl-^` by pressing it twice); escape processing is disabled when stdin is not a TTY, so piped sessions pass bytes through untouched. The session survives roaming between networks, laptop sleep, and flaky links — that's the point of mosh — including recovering from the stale or wedged UDP socket a Wi-Fi/Ethernet switch or sleep/resume can leave behind on Windows: sends and (re)dials are time-bounded, so a blip can't freeze the client itself, only delay it.

SSH authentication tries, in order: an explicit `-i` identity file, every reachable ssh-agent, and an interactive password prompt. The agent chain covers `SSH_AUTH_SOCK`, a running [dotvault](https://github.com/goodtune/dotvault) daemon's SSH agent when present (`$XDG_RUNTIME_DIR/dotvault/agent.sock` or the cache-dir fallback on Linux/macOS, the `\\.\pipe\dotvault-agent` named pipe on Windows — tune with `--dotvault-agent auto|off|<path>`), and Windows' native OpenSSH agent pipe; identities from all of them are offered together. Note the usual agent trade-off: every offered public key (including principals embedded in dotvault-minted certificates) is disclosed to the server you connect to — use `--dotvault-agent off` if that matters for a given host. Host keys verify against `~/.ssh/known_hosts` with `accept-new` semantics by default (`--host-key-policy strict|accept-new|insecure`).

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

All builds are `CGO_ENABLED=0`.

## Status

Interactive sessions, roaming, remote commands, resize, and clean shutdown are implemented and exercised end-to-end in CI against the reference `mosh-server`. Not yet implemented: predictive local echo (mosh's speculative rendering), IP roaming notifications in the status line, and the `MOSH_ESCAPE_KEY` override.

## License

MIT
