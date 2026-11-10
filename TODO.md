# TODO

Phased plan for herdr-auth-proxy. Design rationale, herdr-protocol findings and
decisions live in [ARCHITECTURE.md](ARCHITECTURE.md) (§12 = decisions;
§2 = everything already investigated & verified against herdr 0.9.5).

## Investigated so far (summary)

- herdr repo found & cloned: `github.com/herdrdev/herdr` @ 0.9.5, API protocol 22.
- Protocol fully mapped: JSON API socket (NDJSON, one request/connection,
  streaming exceptions), 103 methods, no auth anywhere, `0600` perms only.
- **No reusable client lib** (single binary crate, unpublished) — but full JSON
  schema available (`herdr api schema --json`, `docs/next/api/herdr-api.schema.json`)
  and the client is ~100 lines to re-implement.
- Env precedence verified: pane env **cannot** override `HERDR_SOCKET_PATH`
  (herdr-managed vars win) → client-side wrapper required (the deployment's
  sandbox wrapper re-points it); `HERDR_AUTH_JWT` passes
  through → JWT rides in pane env, proxy reads it from peer's `/proc/<pid>/environ`.
- Pane metadata tokens **cannot** carry a JWT (80-char value limit).
- opencode integration plugin verified: only `pane.report_agent` /
  `pane.report_agent_session`, fresh connection per call, gated on pane env.
- Bypass analysis: `pane.split`/`tab.create` spawn plain shells (children inherit
  the real socket path) → allowed only with the proxy as env authority; the
  sandbox is the deployment's **bwrap** wrapper (same uid → no uid-based trust);
  `layout.apply` stays denied (explicit argv bypass).

## Phase 0 — scaffold

- [x] Add `justfile` (build, test, clippy, fmt) + rust-toolchain pin (nightly via flake)
- [x] Add `LICENSE` file (Apache-2.0, decided)
- [ ] CI: fmt + clippy + test; optional job that bumps herdr and re-runs deny tests

## Phase 1 — keys & config

- [x] In-memory HS256 signing key generated at proxy startup (never persisted;
      restart invalidates all tokens)
- [x] Process-scoped, orchestrator-scoped bootstrap token handed from the proxy
      to `wrap` over a pipe and set as `HERDR_AUTH_JWT` on herdr; all shells
      inherit it; no bootstrap file. It mints agent/orchestrator tokens but not
      admin
- [x] `config.toml` loading (upstream/auth socket, agent TTL, death grace)
- [x] JWT claim types (sub, role, pane_id, cwd, workspace_id, grants, perm) +
      sign/verify

## Phase 2 — proxy core

- [x] Auth socket listener; accept loop; SO_PEERCRED pid capture (uid is **not**
      used for auth — bwrap keeps the herdr uid)
- [x] NDJSON codec (1 MiB cap, 5s initial timeout — mirror herdr limits)
- [x] One pinned upstream connection per downstream connection; passthrough for
      request/response
- [x] Upstream health ping + watchdog (self-exit after `death_grace_s`)

## Phase 3 — auth

- [x] `auth.hello` wire mode (first line, HS256 verify, exp/nbf)
- [x] Peer-environ extraction mode (`/proc/<pid>/environ` → `HERDR_AUTH_JWT`,
      cross-check `HERDR_PANE_ID` vs claim)
- [x] Fail-closed unauth error (`unauthorized`, close); `auth.whoami`
- [x] Audit log (deny decisions with method/sub/role)

## Phase 4 — policy engine

- [x] Method registry (103 herdr methods, protocol 22) embedded
- [x] Explicit role allowlists (default-deny; no danger-class wildcards)
- [x] Param guards: agent `pane_id`/`target` forcing and ownership; pane-bound
      minting requires an owned pane except for the operator (bootstrap) token;
      `auth.agent.spawn` kind is globally capped
      to `opencode` (args passed through); `layout.apply` denied; **env
      authority** for the atomic spawn path; **cwd/workspace authority**: token
      `cwd` and `workspace_id` are the only directory/workspace for spawn,
      caller overrides rejected; direct `pane.split`/`tab.create`/`agent.start`
      denied to orchestrators
- [x] Owned-only visibility: filter `pane.list`/`agent.list`/`tab.list`
- [x] Default-deny for unknown methods + `[new-command]` WARN logging
- [ ] Compare upstream `ping.protocol` with the embedded registry and warn

## Phase 5 — personas

- [x] `agent` preset (report-only, pane-bound) — verified against a fake
      upstream; still to prove with the real opencode integration plugin
- [x] `orchestrator` preset: **minimal explicit allowlist, default-deny**
      (owned-only reads + own-pane ops + **only** `auth.agent.spawn` for
      creation/start + `auth.token.mint`); direct `pane.split`/`tab.create`/
      `agent.start` denied; nothing else
- [x] Bootstrap `herdr-auth token mint` mints agent or orchestrator tokens;
      bootstrap cannot mint admin; `admin` role remains reserved
- [x] Document & validate the **bwrap wrapper contract** (§ ARCHITECTURE 4.3):
      hides herdr's real socket, `HERDR_SOCKET_PATH` → `auth.sock`,
      `HERDR_AUTH_JWT` passthrough, validates agent args, no fallback

## Phase 6 — minting

- [x] `auth.token.mint`: fixed role minting rules (no `mint_roles` field),
      permission-subset intersection, `exp` clamped to minter `exp` (infinite
      minter → default 24 h), derived child `sub`, `jti` uniqueness
- [x] `auth.agent.spawn` (atomic): `tab.create` → bind pending `jti` to
      `root_pane.pane_id` → `agent.start` (kind whitelist; args passed to the
      wrapper); on failure close the tab + revoke the token
- [x] Grant subset enforcement: requested `grants` ∩ global grantable set ∩
      minter's `agent_grants`; the orchestrator ceiling defaults to the full
      advertised set, agent tokens default to `["report_status"]`; over-request
      → `grant_not_allowed`
- [x] Bootstrap operator may bind an agent token to an existing pane without
      ownership transfer; other non-admin minters remain owned-only
- [x] `wait_own_output` covers own-pane output waits and own-agent lifecycle
      waits; orchestrators may wait for output on owned panes

## Phase 7 — pane ownership

- [x] Record pane/tab/workspace ids from creation responses (`pane.split`,
      `tab.create`, ...) per sub
- [x] Persist ownership across restarts (`state.json`); prune expired tokens
- [x] Enforce on all pane-tab-targeting methods; owned-only list filtering
- [ ] Optional metadata mirror (`auth_owner`, `auth_jti` via
      `pane.report_metadata`)

## Phase 8 — client helper (deferred)

- [x] Decided: v1 ships **no** client-side helper; rely on the deployment's
      sandbox wrapper (contract documented in Phase 5 / ARCHITECTURE §4.3)
- [ ] `herdr-auth-launch` moved to "Later / optional" below

## Phase 9 — lifecycle & packaging

- [x] `herdr-auth-proxy wrap -- herdr "$@"`: resolve the herdr socket like herdr,
      ensure the proxy is running (idempotent), then exec herdr
- [x] `wrap` always exports a valid `HERDR_AUTH_JWT`: on an already-running proxy
      it re-adopts the herdr server's token (verified with `auth.hello`), replaces
      the proxy when no server is running, and fails closed if a running server
      has no usable token (its env cannot be changed externally)
- [x] Proxy daemonizing: `setsid`, log + pidfile, detached from the client
- [x] Self-exit when the upstream has been unreachable for `death_grace_s`;
      `stop`/`status` subcommands
- [x] `herdr-auth` client CLI: `call <method> --json`, `agent spawn`,
      `token mint`, `whoami`, `methods`; JWT via `--token`/`--token-file`/
      `$HERDR_AUTH_JWT` (auth.hello first line) or env fallback
- [x] `herdr-agent` convenience CLI: `spawn`, `list`, `get`, `read`, `prompt`,
      `wait`, and `kill`; prompt text comes from `--text`, `--text-file`, or
      stdin (verbatim, no JSON escaping), waits for idle by default (900 s,
      `--no-wait` opt-out), and sizes the socket timeout to `wait + 60 s`.
      `read` prints terminal text; `kill` closes the pane (`tab.close` with
      `--tab`) after resolving names via `agent.get`
- [x] Grantable-capability validation in the CLI (`--grant`, 4 capabilities)
- [x] Nix packaging: `packages.default` (all binaries), `apps`, `overlays`,
      `nixosModules.default`, `homeManagerModules.default`, `formatter`;
      verified with `nix build .#`
- [ ] README quick-start: install → bootstrap orchestrator token → spawn gated
      opencode agent

## Phase 10 — hardening & tests

- [x] Unit tests: JWT roundtrip/tamper/expiry, grants, policy allowlists,
      ownership/state, environ parsing
- [x] Live-testing hardening: `max_token_ttl_s` hard cap for requested TTLs;
      reject `perm` on agent tokens and `grants` on non-agent tokens; agent
      reports reject foreign panes, pin `agent`/`source`, and reject
      `resume_argv`; CLI flags override inherited `HERDR_AUTH_JWT`; bootstrap
      operator pane binding; own-pane/own-agent wait paths
- [x] Fake-upstream smoke test: hello + environ auth, admin/orchestrator/agent
      personas, owned-only list, pane forcing, atomic spawn, wrap/stop/status
- [ ] Integration test against a real herdr (nix-provided) covering both personas
- [ ] Bypass tests: raw-input methods denied; unknown method denied+logged;
      expired/pane-mismatched tokens rejected; environ without JWT rejected;
      non-whitelisted `agent.start` kind denied; owned-only list filtering;
      bwrap wrapper cannot reach the real socket
- [ ] Streaming tests (`agent.wait`, `agent.prompt --wait`) hold the upstream
      connection until the response
- [ ] `auth.agent.spawn` atomicity tests: failure → tab closed + `jti` revoked;
      grant over-request rejected
- [ ] Fuzz NDJSON framing; slow-client behavior

## Later / optional

- [ ] `herdr-auth-launch` client helper: exec mode (re-point
      `HERDR_SOCKET_PATH`, keep `HERDR_AUTH_JWT`/`HERDR_PANE_ID`, optional uid
      drop) + relay mode (per-client socket + `auth.hello` stamping) — for
      deployments without a sandbox wrapper / unreadable `/proc`
- [ ] Event-stream filtering by ownership
- [ ] Admin minting via a separate control socket (v1: no admin token is issued
      by the bootstrap)
- [ ] Client-socket (binary render protocol) proxying — needs bincode codec,
      frozen enum tags, PROTOCOL_VERSION pinning; explicitly v2
- [ ] Multi-session upstreams; revocation list
