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
- **Authenticates each connection with a JWT** (Ed25519-signed; keypair is generated
  in the config dir on first run) and **filters commands** according to the
  permissions in the JWT.
- Supports two main personas:
  1. **agent** — may only report its own status to herdr (exactly what the herdr
     opencode integration plugin does) and optionally read its own pane.
  2. **orchestrator** — may start agents (kind `opencode`; args are validated by
     the sandbox wrapper), prompt them, read their status, and create/read/close
     panes **it owns** (pane ownership is tracked; list responses are filtered).
     It can *never* send raw shell/pty input, and it can mint scoped child tokens
     for the agents it creates.
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

**Early implementation.** The proxy core works (keys/config/JWT, hello +
peer-environ auth, method allowlists, ownership filtering, mint, atomic spawn,
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

Keys are created in `$XDG_CONFIG_HOME/herdr-auth-proxy/keys/`, state in
`$XDG_STATE_HOME/herdr-auth-proxy/`, and the auth socket in
`$XDG_RUNTIME_DIR/herdr-auth-proxy/`. Bootstrap tokens locally (requires the
private key):

```bash
herdr-auth-proxy mint --role orchestrator --sub orch \
  --perm '{"agent_grants":["report_status","read_own_pane"],"agent_kinds":["opencode"]}'
```

## `herdr-auth` CLI

Ships with the proxy; speaks the same NDJSON envelope plus the `auth.*`
extension methods.

```bash
export HERDR_AUTH_SOCKET="$XDG_RUNTIME_DIR/herdr-auth-proxy/auth.sock"
export HERDR_AUTH_JWT=...            # orchestrator token (or --token-file)

herdr-auth whoami
herdr-auth methods
herdr-auth agent spawn --kind opencode --cwd /work/foo --label foo \
  --grant report_status --grant read_own_pane -- --model sonnet
herdr-auth token mint --role agent --pane w1:p2 --grant report_status
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

## Topology

```
herdr server ── herdr.sock (real, private) ── herdr-auth-proxy ── auth.sock (JWT-gated)
                                                                  ▲            ▲
                                                       gated agent panes   orchestrator
                                                   (sandbox wrapper + env JWT)   (herdr-auth CLI)
```

All client traffic connects only to the proxy; herdr's real socket stays unreachable
for sandboxed identities.

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
