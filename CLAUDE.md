# gosh

Pure-Go mosh (mobile shell) client: SSH bootstrap via `golang.org/x/crypto/ssh`, then mosh's UDP State Synchronization Protocol (AES-128-OCB3 datagrams, zlib-compressed protobuf instructions). `CGO_ENABLED=0` everywhere so one static binary cross-compiles to every Go platform, Windows included.

## Agent workflow: review before pushing

Every Claude agent on this repo runs a five-persona pre-push review of the unpushed changes BEFORE executing `git push`. The personas are security, architecture, cross-platform, test & correctness, and docs & DX. Invoke `/precommit-review` (skill at `.claude/skills/precommit-review/`), address findings in the same commit series — `blocker`/`major` fixed or explicitly declined in a commit message, `minor`/`nit` fixed when cheap — then push once. Skip only when the user explicitly says so or the push is purely administrative. Non-negotiable for code-changing pushes.

## PR descriptions and commit messages

Write PR bodies and long-form commit messages in **flowing prose** — one long line per paragraph or bullet, no manual line wrapping inside a paragraph; GitHub re-wraps at render time and hard-wrapped source churns diffs. Commit-message subject lines stay ~50 chars. Do **not** mention the pre-push review in PR descriptions — it is the default workflow here, and the audit trail lives in the commit series.

## Build & Test

```sh
make test              # unit tests with -race (includes RFC 7253 OCB vectors)
make build             # bin/gosh for the current platform
make build-all         # linux/darwin/windows × amd64/arm64
make integration-test  # testcontainers rig: real sshd + mosh-server (needs Docker)
```

All builds use `CGO_ENABLED=0` — this is a hard invariant; the whole point of the project is a dependency-free cross-compiled binary. Version is injected via ldflags (`-X main.version=...`). Release tags are `v`-prefixed (`v0.1.0`) for Go-module consumption, but `main.version` is the v-stripped semantic version: GoReleaser's `{{.Version}}` strips the prefix and the Makefile strips it via `sed`, so local and release builds agree.

Releases ship via GoReleaser on the GitHub `release: published` event (`.github/workflows/release.yml`). Plain archives only — a client CLI needs no packages, services, or units.

## Architecture

```
cmd/gosh/            CLI (cobra): root session command, connect, version
internal/
  ocb/               AES-128 OCB3 (RFC 7253), pure Go, tested against RFC vectors
  wire/              Hand-rolled proto2 wire codecs for the three frozen mosh
                     messages (TransportInstruction, UserMessage, HostMessage)
  crypto/            Datagram sealing: base64 session key, nonce scheme
                     (4 zero bytes + BE uint64, top bit = direction)
  network/           Client UDP connection: packets with 16-bit timestamp
                     echoes, SRTT/RTTVAR + RTO, replay protection, socket
                     redial on a send failure (Windows-blip recovery) or on
                     mosh's PORT_HOP_INTERVAL timer (a blackholed route that
                     never errors), with dial/write timeouts so a wedged
                     adapter can only delay the client's single
                     input-handling goroutine, never block it outright
  transport/         State Synchronization Protocol: sender state machine
                     (a port of mosh's TransportSender), fragmenter + zlib,
                     receiver dedup/ordering, shutdown handshake
  statesync/         UserStream (keystrokes/resizes) diff/apply/subtract
  bootstrap/         SSH bootstrap: run mosh-server, parse MOSH CONNECT,
                     host-key policies (strict/accept-new/insecure), agent
                     aggregation (SSH_AUTH_SOCK + dotvault socket/pipe +
                     Windows OpenSSH pipe)
  client/            Session loop: input pump, escape handling (Ctrl-^ .),
                     datagram pump, resize watcher (SIGWINCH / Windows poll)
  termenv/           Raw mode + Windows VT-processing enablement
test/integration/    testcontainers: Debian sshd+mosh-server image, library
                     E2E + CLI-binary E2E (behind the `integration` build tag)
```

## Protocol invariants (do not drift)

These mirror the reference mosh implementation (`mobile-shell/mosh`); the integration suite against real `mosh-server` is the arbiter.

- **OCB3 per RFC 7253**, AES-128, 16-byte tag, 12-byte nonce, no associated data. `internal/ocb` is tested against the RFC Appendix A vectors — any change must keep them green.
- **Nonce** = 4 zero bytes + big-endian `uint64` where bit 63 is direction (0 = to-server, 1 = to-client) and bits 0–62 are the packet sequence. The wire datagram carries only the low 8 bytes of the nonce.
- **Packet text** = 2-byte BE timestamp + 2-byte BE timestamp-reply (0xFFFF = none) + payload. `timestamp16` never emits 0xFFFF.
- **Fragments**: 8-byte BE instruction id + 2-byte BE fragment number, top bit = final. Instruction bytes are zlib-compressed before fragmenting; the id changes only when the compressed payload (or MTU) changes, so retransmits reuse it.
- **Instruction protobuf** field numbers are frozen (protocol_version=1 … chaff=7); `MOSH_PROTOCOL_VERSION` is 2. The `wire` package hand-encodes these — field-number changes are protocol breaks, and the fixture tests pin exact bytes.
- **Receiver rule**: gosh is deliberately *stricter* than mosh here — render and acknowledge only an instruction whose `old_num` equals the state currently displayed (`transport.Transport.latestNum`), dedupe by `new_num`, never regress the ack. mosh accepts any still-held reference state because it applies diffs to stored state copies behind a framebuffer; without one, two diffs sharing a reference would paint the shared content twice (the "wwhhoo" doubled-echo bug). Acking only rendered states makes the server re-diff from what is actually on screen. This subsumes mosh's held-state idempotency rule and is a consequence of the no-terminal-emulator design below.
- **Shutdown** is a state numbered `-1` (max uint64), retransmitted until acked (16 tries), whichever side starts it.
- **MTU** is 500 minus 12 (nonce tail + timestamps) minus 16 (OCB tag); the fragmenter subtracts its own 10-byte header.
- **Roaming** relies on `mosh-server` re-learning the client's source `(addr, port)` from the last validly-authenticated packet it receives, per the reference protocol — this is what makes it safe for `internal/network.Connection`'s socket redial (a fresh local ephemeral port after a send failure, or after a port hop) to keep a session alive rather than requiring a stable client-side port.
- **Port hop timer** mirrors mosh's `PORT_HOP_INTERVAL` (10s): `Connection.Send` redials unconditionally once it's been that long since both the last port change and the last confirmed end-to-end round trip (`Connection.SetLastRoundtripSuccess`, fed by `transport.Transport.Recv`'s `NoteRoundtripSuccess` call on every version-matched, successfully reassembled instruction — not gated on the stricter `old_num`/`new_num` acceptance rule below, since even a stale-and-dropped instruction still proves the link round-trips; timestamped to when the now-acknowledged state was originally sent). This is the only defense against a route that blackholes without ever returning a send error — redial-on-error alone (see `internal/network/` below) cannot detect that case, since nothing ever fails. A one-way fault (client→server blocked, server→client heartbeats still arriving) keeps `lastRoundtripSuccess` fresh and suppresses the hop even though the session is effectively dead — mosh has the same blind spot; not fixed here.

## Design decisions

- **No terminal emulator.** The reference client applies server diffs to a local framebuffer and re-renders; gosh writes the diff's `hoststring` bytes straight to the terminal — the diff language *is* ANSI escape sequences. Consequence: diffs are only applied for monotonically increasing state numbers (`transport.Transport.latestNum`) since we cannot re-derive an older screen. This is the main deliberate divergence from mosh, and what predictive echo would require revisiting.
- **Client retries indefinitely.** mosh's sender gates retransmission on `last_heard + ACTIVE_RETRY_TIMEOUT` (a server-quiescence concern); the gosh sender always retries and `RemoteHeard` is bookkeeping-only. A client with pending input has a human attached — giving up silently would be worse than retrying.
- **Hand-rolled proto2 codec** (`internal/wire`) instead of protoc + generated code: the three messages are tiny and frozen since 2012; fixture tests pin the exact bytes.
- **`x/crypto/ssh`, not the system ssh binary**, so Windows needs nothing installed. TERM/LANG ride as quoted env-assignment prefixes on the remote command line (sshd exec goes through the login shell), because `AcceptEnv` can't be assumed.
- **Escape sequence** is fixed at Ctrl-^ (`.` quits, doubled sends literal). Disabled automatically for non-TTY stdin so scripted/piped sessions pass bytes through untouched.
- **dotvault agent by convention, not by dependency.** gosh offers identities from a running [dotvault](https://github.com/goodtune/dotvault) daemon's SSH agent (Unix socket / Windows named pipe, `--dotvault-agent` to override or disable). The endpoint-resolution rule is mirrored in `internal/bootstrap/dotvault.go` rather than importing the dotvault module: dotvault's public `client/` facade deliberately does not export the agent endpoints, the agent speaks the standard SSH agent protocol gosh already consumes, and the dependency would drag in the Vault SDK for two path strings. Keep that file in sync with dotvault's `paths.DefaultAgentSocket` / `config.DefaultAgentPipe` if they ever move.
- **testcontainers integration tests** build a Debian sshd+mosh-server image and are gated behind the `integration` build tag; unit tests must stay Docker-free.

## Testing

- Unit tests per package, table-driven; `go test -race ./...` must pass.
- Interop-sensitive encodings (wire fixtures, OCB vectors, MOSH CONNECT parsing) are pinned byte-exact.
- `test/integration` runs two E2E tests against real mosh-server: library-level (SSH bootstrap → command echo → `exit` shutdown handshake) and CLI-binary-level (`gosh connect` with `MOSH_KEY`). Both must stay green — they are the protocol-conformance oracle.

## Dependency Updates

Dependabot covers `gomod` and `github-actions` at the repo root (`.github/dependabot.yml`). Runtime dependencies are deliberately minimal: cobra, `golang.org/x/{crypto,term,sys}`. testcontainers-go is test-only (kept out of the binary by the `integration` build tag). When introducing a new package ecosystem, extend dependabot in the same PR.
