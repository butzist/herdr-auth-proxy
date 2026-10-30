# AGENTS.md (minimal)

Read **ARCHITECTURE.md** before changing anything security-relevant, and
**TODO.md** for the current phase. Keep both up to date with behavior changes.

## Commands

```bash
nix develop        # devshell (rust nightly, just, jq, ...)
nix build .#       # package both binaries (needs nix-command/flakes enabled)
just build         # or: cargo build
just test          # or: cargo test
just clippy        # cargo clippy -- -D warnings
just fmt           # cargo fmt
```

## Conventions

- Rust nightly, edition 2024. Error handling via `thiserror`; tests may use
  `mockall`. Config is TOML.
- Docs and identifiers use herdr's method names verbatim
  (`pane.report_agent`, `agent.start`, …). Never invent protocol names.

## Invariants — do not break these

1. **Fail closed.** Unknown method, malformed input, unreadable/missing token →
   deny and close. `forward_unknown` must default to `false`.
2. **Default-deny + log.** Every method not in the embedded registry is denied
   with a `[new-command]` WARN log (this is how we learn about new herdr
   commands).
3. **The proxy is the only auth boundary.** herdr has none; never assume
   upstream filters anything. Auth is **JWT-only** — never trust uid (bwrap keeps
   the herdr uid).
4. **Raw-input surface**: `pane.send_text/send_keys/send_input`, `pane.input.set`,
   `agent.send_keys`, `command.invoke` are raw shell access — never allowed to a
   non-admin role. `layout.apply` is denied (explicit argv = unsandboxed code as
   the herdr user). `pane.split`/`tab.create` are allowed only with the proxy as
   env authority (proxy-minted JWT injected, caller env stripped) and only the
   `opencode` kind may be started; agent **args are validated by the sandbox
   wrapper**, not the proxy.
5. **Child tokens are subsets.** Minting intersects permissions; `exp` is clamped
   to the minter's `exp`.
6. **One pinned upstream connection per downstream connection** (streaming
   methods + live handoff depend on it).
7. herdr-managed env vars (`HERDR_SOCKET_PATH`, `HERDR_*_ID`, `HERDR_BIN_PATH`)
   win over caller env in panes — never rely on pane env to redirect them.
8. **No systemd unit.** Lifecycle follows the herdr server: `wrap` starts the
   proxy detached; it exits when the server socket disappears (grace period must
   cover live handoff).
9. **Owned-only visibility.** List/snapshot responses are filtered to the
   caller's owned ids; non-owned detail requests return `forbidden`.
10. **Workflow-only allowlist.** Methods outside the current orchestrator /
    developer / reviewer workflow stay denied (no events, workspace, worktree,
    plugin, integration, layout, UI or raw-input methods) until deliberately
    added.

## Upstream reference

herdr: `github.com/herdrdev/herdr` @ **0.9.5**, API protocol **22**.
Method registry source: `herdr api schema --json` / `docs/next/api/herdr-api.schema.json`.
Bumping herdr = regenerate registry + re-run deny tests (see TODO Phase 4).
