---
name: precommit-review
description: Dispatch a five-persona pre-push code review (security, architecture, cross-platform, test & correctness, docs & DX) against the current branch's unpushed changes. Use BEFORE every `git push` of new commits on a feature branch so findings drive a single clean commit series instead of a noisy round-trip with CI reviewers. Skip only when the user explicitly opts out for the current push, or when the push is purely administrative (rebase pointer update, tag, etc.) and touches no code.
---

# precommit-review

Run the same five review lenses a PR-time CI council would apply, but
locally and before the push, so findings are addressed in-place and the
resulting commit series tells a clear story. This convention is lifted
from goodtune/dotvault, where it replaced a comment-loop CI workflow.

## When to invoke

Before every `git push` of new commits on a feature branch. Skip only
when the user has explicitly said to skip review for this push, or the
push is purely administrative (re-push after a diffless rebase, a tag,
a branch pointer update). If unsure, run it — five short agent calls
are cheap; a public-PR comment loop with a human in the middle is not.

## How

### 1. Determine what's about to be pushed

```sh
git log --oneline @{upstream}..HEAD 2>/dev/null || git log --oneline origin/HEAD..HEAD
git diff @{upstream}..HEAD 2>/dev/null || git diff origin/main...HEAD
```

If the branch has no upstream and `origin/main` doesn't exist either,
fall back to `git status` and `git diff HEAD` so the personas see at
least the uncommitted changes.

### 2. Dispatch the five personas in parallel

Issue **one** message containing five `Agent` tool calls
(`subagent_type=general-purpose`, or `Explore` for read-only lenses on
small diffs). Brief each persona with: branch name and unpushed-commit
summary, the full diff pasted inline, the persona's lens below, the
relevant `CLAUDE.md` sections, and the instruction to **report in under
250 words** with concrete `file:line` references and a severity tag
(`blocker` / `major` / `minor` / `nit`), suppressing "no findings"
filler.

### 3. Triage findings

| Severity | Action |
|----------|--------|
| `blocker` | Address before pushing. No exceptions. |
| `major`   | Address before pushing, or push a commit message that explains the deliberate decision to defer. |
| `minor`   | Fix if cheap. Otherwise mention in the commit message. |
| `nit`     | Fix only if trivially co-located with other changes. |

### 4. Push

`git push -u origin <branch>`.

## Persona briefs

### Security

> Review the diff with a security lens. Cover: the OCB3/crypto layer
> (constant-time tag comparison, nonce uniqueness and direction bits,
> no key material in logs or errors); replay protection and the
> receiver's old_num idempotency rule; host key verification policies
> (no silent trust-on-first-use downgrades, changed keys always fatal);
> shell quoting of everything interpolated into the remote ssh command
> line; parsing of untrusted network input (fragments, protobuf wire,
> MOSH CONNECT output) for panics or unbounded allocation; decompression
> bombs; secrets (MOSH_KEY, passwords) in argv, env, or error text.

### Architecture

> Review the diff with an architectural lens. Cover: package boundaries
> (ocb / wire / crypto / network / transport / statesync / bootstrap /
> client / termenv and their one-way dependency order); fidelity to the
> reference mosh state machines where CLAUDE.md declares invariants;
> goroutine lifecycle and channel ownership in the client loop (no
> leaks, single writer per resource); error handling — fatal versus
> drop-and-continue is a protocol decision, keep it deliberate;
> duplicated logic that belongs in one package.

### Cross-platform / portability

> Review the diff for Linux / macOS / Windows behaviour. Cover: the
> CGO_ENABLED=0 invariant (no cgo, no exec of platform binaries);
> build tags (resize_unix/resize_windows, vt_windows); Windows console
> VT enablement and raw mode; SIGWINCH absence on Windows; path
> handling (known_hosts under %USERPROFILE%); goreleaser target list;
> anything assuming a Unix shell locally (remote-side sh is fine —
> sshd guarantees it).

### Test & correctness

> Review the diff for test coverage and behavioural correctness.
> Cover: tests for changed code; table-driven idioms; byte-exact
> fixtures for interop-sensitive encodings (wire format, OCB vectors);
> whether assertions are load-bearing (would the test fail if the
> production change were reverted?); flake risk (sleeps, timing
> assumptions, fixed ports) especially in the testcontainers suite;
> `go test -race` cleanliness; edge cases the diff implies (wraparound
> of 16-bit timestamps, uint64(-1) shutdown sentinel, empty diffs,
> fragment reordering).

### Docs & DX

> Review the diff for docs and developer-experience drift. Cover:
> CLAUDE.md / README.md alignment with the change (especially the
> "Protocol invariants" section); CLI help text; error messages a user
> acts on; comments describing code that no longer exists; Makefile /
> goreleaser / workflow drift; `.github/dependabot.yml` entries when a
> new package ecosystem appears.

## Anti-patterns this skill exists to avoid

- **Push-then-review.** Findings arriving after the push force either
  history rewrites or noisy fix commits. Pre-push review fixes once,
  pushes once.
- **Repeated dispatch in a tight loop.** A one-line fix that an earlier
  review explicitly flagged doesn't need a fresh council; reference the
  earlier finding in the commit message.
- **Asking the personas to fix things.** Personas review and report;
  the fix is the author's.
