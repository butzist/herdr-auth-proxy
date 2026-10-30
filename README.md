# herdr-auth-proxy

An authenticating, authorizing proxy in front of [herdr](https://github.com/herdrdev/herdr)'s
unix socket API.

herdr has **no authentication** on its sockets — the only protection is `0600` file
permissions (same-user only). Any process running as the herdr user can do anything:
spawn panes, type into any terminal, stop the server. `herdr-auth-proxy` turns that
single flat socket into a JWT-gated socket with per-identity command filtering, so
sandboxed/untrusted agents and orchestrators can be given exactly the access they
need — and nothing more.

## What it does

- Runs as a **lifecycle wrapper around the `herdr` command** (no systemd): it
  starts detached, proxies herdr's JSON API protocol (NDJSON over unix socket),
  and exits when the herdr server goes away.
- **Authenticates each connection with a JWT** (HS256, signed with a random key
  generated in memory at proxy startup; no key file) and **filters commands**
  according to the permissions in the JWT. A proxy restart invalidates all
  outstanding tokens.
- Supports two main personas:
  1. **agent** — may only report its own status to herdr (exactly what the herdr
     opencode integration plugin does) and optionally read its own pane.
  2. **orchestrator** — may start agents **only through the atomic
     `auth.agent.spawn`** (kind `opencode`; args are validated by the sandbox
     wrapper), prompt them, read their status, and read/close panes **it owns**
     (pane ownership is tracked; list responses are filtered). It cannot create
     plain panes and can *never* send raw shell/pty input. It can mint scoped
     child tokens for the agents it creates.
- Works with your existing **bwrap sandbox wrapper** (e.g. an `opencode` wrapper
  that hides herdr's real socket in a mount namespace): it only needs to set
  `HERDR_SOCKET_PATH` to the proxy socket, pass `HERDR_AUTH_JWT` through, and
  validate agent args. Unmodified herdr clients and plugins (including the
  opencode integration) then work through the proxy with **zero changes** — the
  proxy picks the token up from the connecting peer's environment. Auth is
  JWT-only; uid is *not* trusted (bwrap keeps the herdr uid).
- **Default-deny to the workflow**: only methods needed by the orchestrator
  (spawn/prompt/read/close owned panes) and status-reporting agents are allowed;
  everything else is refused (no layout, events, worktree, plugin, integration,
  UI or raw-input methods).
- Logs every unknown/new herdr method (still denied) so policy can be updated
  when herdr adds commands.

## Status

**Early implementation.** The proxy core works (in-memory signing key/config/JWT,
hello + peer-environ auth, method allowlists, ownership filtering, mint, atomic spawn,
`wrap`/`stop`/`status`) and the `herdr-auth` CLI is complete. Validated against a
fake upstream; not yet against a real herdr. See
[ARCHITECTURE.md](ARCHITECTURE.md) (design, herdr findings, diagrams, decisions)
and [TODO.md](TODO.md) (remaining work).

## Install (Nix)

The flake builds both binaries (`herdr-auth-proxy`, `herdr-auth`):

```nix
# flake.nix
inputs.herdr-auth-proxy.url = "github:butzist/herdr-auth-proxy";
```

```nix
# NixOS: either add the package …
environment.systemPackages = [
  inputs.herdr-auth-proxy.packages.${pkgs.system}.default
];

# … or use the module
imports = [ inputs.herdr-auth-proxy.nixosModules.default ];
programs.herdr-auth-proxy.enable = true;

# home-manager
imports = [ inputs.herdr-auth-proxy.homeManagerModules.default ];
```

There is **no systemd unit by design** — start the proxy together with herdr:

```bash
herdr-auth-proxy wrap -- herdr
```

The signing key is generated **in memory** at proxy startup and is never written
to disk. There is no private-key file to protect. State lives in
`$XDG_STATE_HOME/herdr-auth-proxy/`; the auth socket and pid file live in
`$XDG_RUNTIME_DIR/herdr-auth-proxy/`. **No bootstrap token is written to disk.**

`herdr-auth-proxy wrap` starts the proxy, receives a process-scoped bootstrap
token from it over a pipe, and sets that token as `HERDR_AUTH_JWT` in the herdr
process environment. Herdr passes that environment to every shell it spawns, so
`herdr-auth token mint` works from any shell. The bootstrap token is
**orchestrator-scoped**: it can mint agent or orchestrator tokens, but never
admin tokens. `--cwd` and `--workspace` are required when minting an
orchestrator token.

`wrap` also works when the proxy is already running: it re-adopts the token the
running herdr server carries (verifying it with the current proxy) instead of
silently leaving the session without one. If the proxy is running but the herdr
server is not, `wrap` replaces the proxy so it gets a fresh bootstrap token. If
a herdr server is already running **without** a usable token, `wrap` fails with
a clear error — restart that server (`herdr server stop`) and run `wrap` again.

```bash
herdr-auth-proxy wrap -- herdr

# In a shell pane created by herdr (it inherits HERDR_AUTH_JWT):
export HERDR_AUTH_JWT="$(
  herdr-auth token mint --role orchestrator --sub orch --cwd /work --workspace w1 \
    --perm '{"agent_grants":["report_status","read_own_pane"],"agent_kinds":["opencode"]}' \
  | jq -r .token
)"
```

`herdr-auth-proxy` manages the proxy session (`serve`, `wrap`, `stop`,
`status`); token minting and agent operations are in `herdr-auth`.

Pane-bound agent tokens can only be minted for a pane the minter owns; the
bootstrap token owns no panes. Use `auth.agent.spawn` (or an orchestrator token)
to create/bind agent tokens.

`mint` uses `HERDR_AUTH_JWT` from its environment unless `--token` or
`--token-file` is given; explicit flags always win over the environment, so
testing a minted agent token does not silently fall back to the inherited
orchestrator token. Because every shell inherits the bootstrap token, any
command in a user shell can mint agent/orchestrator tokens; that is the
trade-off of the env-based design. The herdr **server** must
be started through `wrap` (or restarted under it) so it inherits the token;
`wrap` reuses the running server's token when possible and errors when the
server has none (a running server's environment cannot be changed from outside).
The bootstrap token is visible through `/proc/<pid>/environ` to same-uid
processes. **Restarting the
proxy invalidates every token**, so re-mint after a restart. Any `keys/`
directory left by an older version is now ignored and may be deleted.

Panes created by `auth.agent.spawn` get a freshly minted **agent** token in
their pane environment, overriding the inherited bootstrap token. Panes created
directly in the herdr TUI (outside the proxy) keep the bootstrap token, so the
sandbox wrapper must reject non-agent tokens and must not be run in such a pane
with the inherited token.

`--cwd` and `--workspace` are the token's only working directory and workspace.
Panes and agents created with that token are always opened there; callers
cannot override either value.

## Minting requirements

Role minting is fixed; it is not configurable through a mutable `mint_roles`
list.

| Minter token | May mint | Notes |
|---|---|---|
| **bootstrap** (`wrap`) | `agent`, `orchestrator` | never `admin`; orchestrator requires `cwd` **and** `workspace_id` |
| **orchestrator** | `agent` only | grants must be a subset of its `agent_grants`; `cwd`/`workspace_id` are inherited |
| **agent** | nothing | cannot mint |
| **admin** | any | reserved; not issued by bootstrap |

Additional rules:

- `--cwd` is required for orchestrator tokens and must be an existing absolute
  directory. `--workspace` is required and must be non-empty.
- Agent tokens inherit the minter's `cwd`/`workspace_id`; they cannot change
  them. Agent tokens may omit `cwd`/`workspace_id` when the minter is the
  bootstrap token.
- `--pane` is valid only for agent tokens, and only if the minter owns that
  pane. The bootstrap token owns no panes, so pane-bound agent tokens come from
  `auth.agent.spawn` or an orchestrator that owns the pane.
- `--sub` is a label suffix only. The token `sub` is always derived as
  `minter:jti[:label]`; a caller cannot choose a bare `sub` or impersonate
  another owner.
- `perm.agent_grants` is intersected with the global grantable set and the
  minter's grants. An orchestrator whose token has no `perm.agent_grants` may
  grant any advertised capability; set `perm.agent_grants` to narrow that
  ceiling. `perm.agent_kinds` can only narrow the global sandboxed kind list
  (`opencode`); it cannot widen it. `perm.mint_max_ttl_s` caps child TTL.
  `perm` is only valid for orchestrator tokens; `grants` are only valid for
  agent tokens. `mint_roles` no longer exists.
- Child `exp` is clamped to the minter's `exp`, its `mint_max_ttl_s`, and the
  proxy-wide `max_token_ttl_s` (default 24 h). Agent tokens default to
  `agent_ttl_s` (24 h); orchestrator tokens have no default expiry unless
  `--ttl_s` is supplied.
- `herdr-auth token mint` defaults to `--role agent`; pass `--role orchestrator`
  for the initial bootstrap token. `herdr-auth-proxy` has no mint subcommand.

## `herdr-auth` CLI

Ships with the proxy; speaks the same NDJSON envelope plus the `auth.*`
extension methods. This is the command used for token minting and agent
operations; `herdr-auth-proxy` only manages the proxy session.

```bash
export HERDR_AUTH_SOCKET="$XDG_RUNTIME_DIR/herdr-auth-proxy/auth.sock"
export HERDR_AUTH_JWT=...            # orchestrator token (or --token-file)

herdr-auth whoami
herdr-auth methods
herdr-auth agent spawn --kind opencode --label foo \
  --grant report_status --grant read_own_pane -- --model sonnet
# pane-bound mint requires the caller to own w1:p2:
herdr-auth token mint --role agent --pane w1:p2 --grant report_status
# optional: --cwd/--workspace must match the caller token, they cannot change it
herdr-auth call agent.list --params '{}'
```

Start/stop together with the herdr server (no systemd unit):

```bash
herdr-auth-proxy wrap -- herdr      # ensures the proxy, then runs herdr
herdr-auth-proxy status
herdr-auth-proxy stop
```

Grantable agent capabilities: `report_status`, `report_metadata`,
`read_own_pane`, `wait_own_output` (see ARCHITECTURE §5).

An agent token is pinned to its pane and to the `opencode` reporting identity:
a report for another pane is rejected, and `agent`/`source` cannot be changed.
`pane.report_agent` accepts `idle | working | blocked | unknown`; `done` is
derived by herdr's tool integration and is rejected by herdr itself.
`resume_argv` is rejected for agent tokens (herdr would execute it on restore).

## Topology

```
herdr server ── herdr.sock (real, private) ── herdr-auth-proxy ── auth.sock (JWT-gated)
                                                                  ▲            ▲
                                                       gated agent panes   orchestrator
                                                   (sandbox wrapper + env JWT)   (herdr-auth CLI)
```

All client traffic connects only to the proxy; herdr's real socket stays unreachable
for sandboxed identities.

## Sandbox wrapper requirements

The proxy cannot enforce the sandbox from the outside. The deployment's `bwrap`
wrapper must, in the sandbox's mount namespace:

1. **Always bind `/dev/null` over every real herdr socket.** Do this even if the
   herdr config directory is already hidden — it is defense in depth:
   - `herdr.sock`
   - `herdr-client.sock`
   - the active session socket and its `-client` sibling
     (`.../sessions/<name>/herdr.sock` and `.../herdr-client.sock`)
   - the default `$XDG_CONFIG_HOME/herdr/herdr.sock` and `herdr-client.sock`
   - any custom `HERDR_SOCKET_PATH` inherited by the pane and its `-client`
     sibling

   Example:
   ```sh
   --bind /dev/null "$HERDR_CONFIG/herdr.sock" \
   --bind /dev/null "$HERDR_CONFIG/herdr-client.sock" \
   --bind /dev/null "$HERDR_SESSION_DIR/herdr.sock" \
   --bind /dev/null "$HERDR_SESSION_DIR/herdr-client.sock"
   ```
   A bind-mounted `/dev/null` is not a socket: `connect()` fails even if the path
   is visible, so a stray bind or a forgotten hide cannot bypass the proxy.

2. Bind **only the proxy's `auth.sock`** from the runtime dir. Do not bind the
   whole runtime directory.
3. Use a **private PID namespace and `/proc`** (`--unshare-pid --proc /proc`).
   Without it, the agent can read `/proc/<pid>/environ` and obtain the inherited
   bootstrap orchestrator token from herdr or other same-uid processes, even
   though its own pane was given a minted agent token.
4. Set `HERDR_SOCKET_PATH` to the sandboxed `auth.sock` path and pass
   `HERDR_AUTH_JWT` through. Strip the real socket path and all other inherited
   `HERDR_*` variables.
5. Validate agent arguments (the proxy only whitelists the `kind`), refuse
   path-changing flags such as `--cwd`, and set the agent's cwd to the token's
   `cwd` claim (see ARCHITECTURE §4.3).
6. Never fall back to herdr's original `HERDR_SOCKET_PATH` if anything fails;
   abort instead.

Orchestrators are not allowed to create plain panes: `pane.split`, `tab.create`
and `agent.start` are denied. Every orchestrator-created pane goes through
`auth.agent.spawn`, which injects the token/cwd/env and starts the wrapper in
one operation.

## Development

```bash
nix develop          # rust nightly + tooling
cargo build          # build
cargo test           # tests
cargo clippy         # lint
nix build .#         # package both binaries into ./result/bin
```

Upstream herdr facts are pinned against **herdr 0.9.5 (API protocol 22)** — see
ARCHITECTURE.md for the method registry source and how to regenerate it.

## License

Apache-2.0 (matching herdr). No `LICENSE` file has been added yet — see TODO.md.
