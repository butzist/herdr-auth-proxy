//! The proxy server: accept, authenticate, filter, forward.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::BufReader;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, watch};

use crate::config::Paths;
use crate::jwt::{Claims, Perm, Role};
use crate::mail::MailHub;
use crate::store::{Message, NewMessage, Principal, Store};
use crate::{config, cwd, environ, grants, jwt, keys, policy, protocol, state::State, upstream};

struct Ctx {
    cfg: config::Config,
    paths: Paths,
    keys: keys::Keys,
    state: Mutex<State>,
    store: Store,
    mail: Arc<MailHub>,
    bootstrap_jti: String,
}

struct Identity {
    sub: String,
    role: Role,
    grants: Vec<String>,
    perm: Option<Perm>,
    pane_id: Option<String>,
    cwd: Option<String>,
    workspace_id: Option<String>,
    jti: String,
    exp: Option<u64>,
}

pub async fn run() -> Result<(), String> {
    let (cfg, paths) = config::load()?;
    let keys = keys::Keys::generate()?;
    let bootstrap_claims = bootstrap_claims();
    let bootstrap_jti = bootstrap_claims.jti.clone();
    let store = Store::open(&paths.state_db).await?;
    let now = jwt::now();
    store.record_principal(&bootstrap_claims, None, now).await?;
    let mut state = store.load_state().await?;
    state.prune(now);
    store.prune_tokens(now).await?;
    let ctx = Arc::new(Ctx {
        cfg,
        paths: paths.clone(),
        keys,
        state: Mutex::new(state),
        store,
        mail: Arc::new(MailHub::new()),
        bootstrap_jti,
    });

    prepare_socket(&paths).await?;
    let listener = UnixListener::bind(&paths.auth_socket)
        .map_err(|error| format!("bind {}: {error}", paths.auth_socket.display()))?;
    let _ = std::fs::set_permissions(&paths.auth_socket, std::fs::Permissions::from_mode(0o666));
    write_pid(&paths)?;
    let bootstrap = jwt::mint(&ctx.keys, &bootstrap_claims)?;
    if std::env::var_os("HERDR_AUTH_BOOTSTRAP_STDOUT").is_some() {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{bootstrap}")
            .and_then(|_| stdout.flush())
            .map_err(|error| format!("write bootstrap token: {error}"))?;
    }
    eprintln!(
        "herdr-auth-proxy: listening on {} (upstream {})",
        paths.auth_socket.display(),
        paths.upstream_socket.display()
    );

    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    spawn_signal_handler(shutdown_tx.clone());
    spawn_watchdog(ctx.clone(), shutdown_tx);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let ctx = ctx.clone();
                        tokio::spawn(async move {
                            if let Err(error) = handle_connection(stream, ctx).await {
                                eprintln!("herdr-auth-proxy: connection error: {error}");
                            }
                        });
                    }
                    Err(error) => eprintln!("herdr-auth-proxy: accept: {error}"),
                }
            }
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }

    let _ = tokio::fs::remove_file(&paths.auth_socket).await;
    let _ = tokio::fs::remove_file(&paths.pid_file).await;
    eprintln!("herdr-auth-proxy: stopped");
    Ok(())
}

fn bootstrap_claims() -> Claims {
    let now = jwt::now();
    Claims {
        iss: jwt::ISS.into(),
        sub: "bootstrap".into(),
        jti: jwt::random_id(),
        iat: now,
        nbf: now,
        exp: None,
        // The bootstrap token gets the orchestrator permission set, not admin.
        // It can mint the first orchestrator token but cannot mint admin or
        // directly create plain panes (see ORCHESTRATOR_METHODS).
        role: Role::Orchestrator,
        pane_id: None,
        cwd: None,
        workspace_id: None,
        grants: Vec::new(),
        perm: None,
    }
}

async fn prepare_socket(paths: &Paths) -> Result<(), String> {
    if let Some(parent) = paths.auth_socket.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    if paths.auth_socket.exists() {
        if UnixStream::connect(&paths.auth_socket).await.is_ok() {
            return Err("another proxy is already listening".into());
        }
        let _ = tokio::fs::remove_file(&paths.auth_socket).await;
    }
    Ok(())
}

fn write_pid(paths: &Paths) -> Result<(), String> {
    if let Some(parent) = paths.pid_file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    std::fs::write(&paths.pid_file, std::process::id().to_string())
        .map_err(|error| format!("write pid: {error}"))
}

fn spawn_signal_handler(tx: watch::Sender<bool>) {
    tokio::spawn(async move {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        match &mut terminate {
            Some(terminate) => {
                tokio::select! {
                    _ = terminate.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            None => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
        let _ = tx.send(true);
    });
}

fn spawn_watchdog(ctx: Arc<Ctx>, tx: watch::Sender<bool>) {
    tokio::spawn(async move {
        let grace = ctx.cfg.death_grace_s.max(5);
        let mut seen = false;
        let mut down_for = 0u64;
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let alive = upstream::request(&ctx.paths.upstream_socket, "ping", json!({}), "health")
                .await
                .is_ok();
            if alive {
                seen = true;
                down_for = 0;
            } else if seen {
                down_for += 5;
                if down_for >= grace {
                    eprintln!("herdr-auth-proxy: upstream went away; exiting");
                    let _ = tx.send(true);
                    break;
                }
            }
        }
    });
}

async fn handle_connection(stream: UnixStream, ctx: Arc<Ctx>) -> Result<(), String> {
    let peer = stream.peer_cred().ok();
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let first = match tokio::time::timeout(Duration::from_secs(5), protocol::read_line(&mut reader))
        .await
    {
        Ok(Ok(Some(line))) => line,
        Ok(Ok(None)) | Err(_) => return Ok(()),
        Ok(Err(error)) => return Err(error.to_string()),
    };
    let mut request: Value =
        serde_json::from_str(&first).map_err(|error| format!("invalid request: {error}"))?;

    let identity = if protocol::method_of(&request) == "auth.hello" {
        let token = request
            .pointer("/params/jwt")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let claims = jwt::verify(&ctx.keys, token)?;
        let identity = identity_from_claims(&ctx, claims).await?;
        let id = protocol::id_of(&request);
        let response = protocol::ok(
            &id,
            json!({"ok": true, "sub": identity.sub, "role": identity.role}),
        );
        protocol::write_line(&mut write_half, &response)
            .await
            .map_err(|error| format!("write hello: {error}"))?;
        let next = protocol::read_line(&mut reader)
            .await
            .map_err(|error| format!("read request: {error}"))?
            .ok_or_else(|| "connection closed after auth.hello".to_string())?;
        request =
            serde_json::from_str(&next).map_err(|error| format!("invalid request: {error}"))?;
        identity
    } else {
        let token = match peer.and_then(|cred| cred.pid()) {
            Some(pid) => environ::var_from_pid(pid, "HERDR_AUTH_JWT").await,
            None => None,
        };
        let Some(token) = token else {
            let id = protocol::id_of(&request);
            let response = protocol::error(&id, "unauthorized", "missing or invalid JWT");
            protocol::write_line(&mut write_half, &response)
                .await
                .map_err(|error| format!("write unauthorized: {error}"))?;
            return Ok(());
        };
        let claims = jwt::verify(&ctx.keys, &token)?;

        // Cross-check the pane claim against the peer's environment.
        if let (Some(pid), Some(claim)) =
            (peer.and_then(|cred| cred.pid()), claims.pane_id.as_deref())
            && let Some(actual) = environ::var_from_pid(pid, "HERDR_PANE_ID").await
            && actual != claim
        {
            let id = protocol::id_of(&request);
            let response = protocol::error(
                &id,
                "unauthorized",
                "HERDR_PANE_ID does not match the token",
            );
            protocol::write_line(&mut write_half, &response)
                .await
                .map_err(|error| format!("write unauthorized: {error}"))?;
            return Ok(());
        }
        identity_from_claims(&ctx, claims).await?
    };

    let response = dispatch(&ctx, &identity, &request).await;
    protocol::write_line(&mut write_half, &response)
        .await
        .map_err(|error| format!("write response: {error}"))?;
    Ok(())
}

async fn identity_from_claims(ctx: &Ctx, claims: Claims) -> Result<Identity, String> {
    let pane_id = match claims.pane_id.clone() {
        Some(pane) => Some(pane),
        None => {
            let state = ctx.state.lock().await;
            state.pane_of_token(&claims.jti)
        }
    };
    ctx.store.touch_principal(&claims, jwt::now()).await?;
    Ok(Identity {
        sub: claims.sub,
        role: claims.role,
        grants: claims.grants,
        perm: claims.perm,
        pane_id,
        cwd: claims.cwd,
        workspace_id: claims.workspace_id,
        jti: claims.jti,
        exp: claims.exp,
    })
}

/// Agent tokens are pinned to one pane and one reporting identity.
///
/// A supplied pane that differs from the claim is rejected instead of being
/// silently rewritten, so a caller cannot believe it wrote to another pane.
/// Reporting is fixed to the only sandboxed agent kind: an agent cannot relabel
/// its pane as another agent, and it cannot inject `resume_argv` (herdr executes
/// that command on restore as the herdr user).
fn enforce_agent_params(
    identity: &Identity,
    method: &str,
    params: &mut Value,
) -> Result<(), (String, String)> {
    let Some(pane) = identity.pane_id.as_deref() else {
        return Err((
            "forbidden".to_string(),
            "agent token is not bound to a pane".to_string(),
        ));
    };

    if matches!(
        method,
        "pane.report_agent"
            | "pane.report_agent_session"
            | "pane.report_metadata"
            | "pane.get"
            | "pane.read"
            | "pane.wait_for_output"
    ) {
        if let Some(requested) = policy::pane_id_param(params)
            && requested != pane
        {
            return Err((
                "forbidden".to_string(),
                "pane is fixed by the token".to_string(),
            ));
        }
        if let Some(object) = params.as_object_mut() {
            object.remove("target_pane_id");
        }
        params["pane_id"] = json!(pane);
    }

    if matches!(method, "agent.get" | "agent.wait") {
        if let Some(requested) = policy::agent_target_pane(params)
            && requested != pane
        {
            return Err((
                "forbidden".to_string(),
                "agent pane is fixed by the token".to_string(),
            ));
        }
        params["target"] = json!(pane);
    }

    if matches!(
        method,
        "pane.report_agent" | "pane.report_agent_session" | "pane.report_metadata"
    ) {
        enforce_agent_reporting_identity(params)?;
    }

    Ok(())
}

/// Fix the reported agent/source to the only allowed sandboxed kind and reject
/// herdr's resume-command field.
fn enforce_agent_reporting_identity(params: &mut Value) -> Result<(), (String, String)> {
    if params
        .get("resume_argv")
        .is_some_and(|value| !value.is_null())
    {
        return Err((
            "forbidden".to_string(),
            "resume_argv is not allowed for agent tokens".to_string(),
        ));
    }
    let agent = policy::SANDBOXED_AGENT_KINDS[0];
    let source = format!("herdr:{agent}");
    if let Some(requested) = params.get("agent").and_then(Value::as_str)
        && requested != agent
    {
        return Err((
            "forbidden".to_string(),
            "agent identity is fixed by the token".to_string(),
        ));
    }
    if let Some(requested) = params.get("source").and_then(Value::as_str)
        && requested != source
    {
        return Err((
            "forbidden".to_string(),
            "report source is fixed by the token".to_string(),
        ));
    }
    params["agent"] = json!(agent);
    params["source"] = json!(source);
    Ok(())
}

async fn dispatch(ctx: &Arc<Ctx>, identity: &Identity, request: &Value) -> String {
    let id = protocol::id_of(request);
    let method = protocol::method_of(request).to_string();
    let mut params = protocol::params_of(request);

    if method.starts_with("auth.") {
        let result = match method.as_str() {
            "auth.whoami" => Ok(json!({
                "sub": identity.sub,
                "role": identity.role,
                "grants": identity.grants,
                "pane_id": identity.pane_id,
                "cwd": identity.cwd,
                "workspace_id": identity.workspace_id,
                "jti": identity.jti,
                "exp": identity.exp,
            })),
            "auth.methods" => Ok(json!({
                "known": policy::KNOWN_METHODS,
                "orchestrator": policy::ORCHESTRATOR_METHODS,
                "agent_grants": grants::GRANTABLE_AGENT_CAPABILITIES,
                "messages": [
                    "auth.message.send",
                    "auth.message.poll",
                    "auth.message.notify",
                    "auth.message.ack",
                    "auth.message.status",
                    "auth.message.peer.grant",
                    "auth.message.peer.revoke",
                    "auth.message.peer.list",
                ],
                "admin_only": ["pane.read"],
            })),
            "auth.token.mint" => mint(ctx, identity, &params).await,
            "auth.agent.spawn" => spawn(ctx, identity, &params).await,
            "auth.message.send" => message_send(ctx, identity, &params).await,
            "auth.message.poll" => message_poll(ctx, identity, &params).await,
            "auth.message.notify" => message_notify(ctx, identity, &params).await,
            "auth.message.ack" => message_ack(ctx, identity, &params).await,
            "auth.message.status" => message_status(ctx, identity, &params).await,
            "auth.message.peer.grant" => peer_grant(ctx, identity, &params).await,
            "auth.message.peer.revoke" => peer_revoke(ctx, identity, &params).await,
            "auth.message.peer.list" => peer_list(ctx, identity, &params).await,
            _ => Err((
                "unknown_method".to_string(),
                "unknown auth method".to_string(),
            )),
        };
        return match result {
            Ok(result) => protocol::ok(&id, result),
            Err((code, message)) => {
                eprintln!(
                    "herdr-auth-proxy: deny {} sub={} ({code}: {message})",
                    method, identity.sub
                );
                protocol::error(&id, &code, &message)
            }
        };
    }

    if !policy::is_known(&method) {
        eprintln!(
            "[new-command] unknown method {method} sub={} role={}",
            identity.sub,
            identity.role.as_str()
        );
        return protocol::error(&id, "unknown_method", "method not known to the proxy");
    }
    if !policy::allowed_for(identity.role, &method, &identity.grants) {
        eprintln!(
            "herdr-auth-proxy: deny {method} sub={} role={}",
            identity.sub,
            identity.role.as_str()
        );
        return protocol::error(&id, "forbidden", "method not allowed for this role");
    }

    if identity.role == Role::Agent
        && let Err((code, message)) = enforce_agent_params(identity, &method, &mut params)
    {
        return protocol::error(&id, &code, &message);
    }

    if identity.role != Role::Admin {
        let state = ctx.state.lock().await;
        if let Some(pane) = policy::pane_id_param(&params)
            && identity.pane_id.as_deref() != Some(pane)
            && !state.owns_pane(pane, &identity.sub)
        {
            return protocol::error(&id, "forbidden", "pane not owned by caller");
        }
        if let Some(tab) = policy::tab_id_param(&params)
            && !state.owns_tab(tab, &identity.sub)
        {
            return protocol::error(&id, "forbidden", "tab not owned by caller");
        }
        if let Some(pane) = policy::agent_target_pane(&params)
            && identity.pane_id.as_deref() != Some(pane)
            && !state.owns_pane(pane, &identity.sub)
        {
            return protocol::error(&id, "forbidden", "agent pane not owned by caller");
        }
    }

    // Agent names are resolved to a pane before forwarding; pane-id targets
    // were already checked above.
    if identity.role != Role::Admin
        && matches!(
            method.as_str(),
            "agent.get" | "agent.read" | "agent.wait" | "agent.prompt"
        )
        && let Some(target) = policy::agent_target(&params)
        && !target.contains(':')
    {
        match check_agent_name_target(ctx, identity, target).await {
            Ok(()) => {}
            Err((code, message)) => return protocol::error(&id, &code, &message),
        }
    }

    if method == "agent.start" {
        let kind = params
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let allowed = identity
            .perm
            .as_ref()
            .map(|perm| perm.agent_kinds.clone())
            .filter(|kinds| !kinds.is_empty())
            .map(|kinds| {
                kinds
                    .into_iter()
                    .filter(|kind| policy::SANDBOXED_AGENT_KINDS.contains(&kind.as_str()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| {
                policy::SANDBOXED_AGENT_KINDS
                    .iter()
                    .map(|kind| (*kind).to_string())
                    .collect()
            });
        if !allowed.iter().any(|allowed| allowed == kind) {
            return protocol::error(&id, "forbidden", "agent kind not allowed");
        }
        if identity.role != Role::Admin || identity.cwd.is_some() {
            match check_agent_start_cwd(ctx, identity, &params).await {
                Ok(()) => {}
                Err((code, message)) => return protocol::error(&id, &code, &message),
            }
        }
    }

    // A token's `cwd` is authoritative for pane creation. Callers may repeat
    // the same value but can never choose a different directory.
    let mut enforced_cwd: Option<String> = None;
    let enforce = matches!(method.as_str(), "pane.split" | "tab.create")
        && (identity.role != Role::Admin || identity.cwd.is_some());
    if enforce {
        match enforce_cwd(identity, &mut params) {
            Ok(value) => enforced_cwd = value,
            Err((code, message)) => return protocol::error(&id, &code, &message),
        }
    }
    let recorded_cwd = enforced_cwd
        .clone()
        .or_else(|| params.get("cwd").and_then(Value::as_str).map(str::to_owned));

    // A token's workspace is authoritative for pane creation.
    let mut enforced_workspace: Option<String> = None;
    let enforce_workspace = matches!(method.as_str(), "pane.split" | "tab.create")
        && (identity.role != Role::Admin || identity.workspace_id.is_some());
    if enforce_workspace {
        match enforce_workspace_id(identity, &mut params) {
            Ok(value) => enforced_workspace = value,
            Err((code, message)) => return protocol::error(&id, &code, &message),
        }
    }

    // Env authority: for non-admin pane creation the proxy builds the env and
    // injects a pending pane token. Caller env is discarded (no PATH/LD_* games).
    let mut pending_jti: Option<String> = None;
    if identity.role != Role::Admin && matches!(method.as_str(), "pane.split" | "tab.create") {
        let jti = jwt::random_id();
        let now = jwt::now();
        let exp = clamp_exp(
            Some(now.saturating_add(ctx.cfg.agent_ttl_s.min(ctx.cfg.max_token_ttl_s))),
            identity.exp,
            identity.perm.as_ref().and_then(|perm| perm.mint_max_ttl_s),
            now,
        );
        let claims = Claims {
            iss: jwt::ISS.into(),
            sub: format!("{}:{}", identity.sub, &jti[..8]),
            jti: jti.clone(),
            iat: now,
            nbf: now,
            exp,
            role: Role::Agent,
            pane_id: None,
            cwd: enforced_cwd.clone(),
            workspace_id: enforced_workspace.clone(),
            grants: vec!["report_status".into()],
            perm: None,
        };
        let token = match jwt::mint(&ctx.keys, &claims) {
            Ok(token) => token,
            Err(error) => return protocol::error(&id, "internal", &error),
        };
        params["env"] = json!({ "HERDR_AUTH_JWT": token });
        if let Err(error) = ctx
            .store
            .record_principal(&claims, Some((&identity.jti, &identity.sub)), now)
            .await
        {
            return protocol::error(&id, "internal", &error);
        }
        {
            let mut state = ctx.state.lock().await;
            state.tokens.insert(
                jti.clone(),
                crate::state::TokenEntry {
                    sub: identity.sub.clone(),
                    pane_id: None,
                    exp,
                },
            );
        }
        pending_jti = Some(jti);
    }

    let upstream_id = format!("proxy-{}", jwt::random_id());
    match upstream::request(&ctx.paths.upstream_socket, &method, params, &upstream_id).await {
        Ok(mut result) => {
            let snapshot = {
                let mut state = ctx.state.lock().await;
                policy::record_created(
                    &method,
                    &result,
                    &mut state,
                    &identity.sub,
                    &identity.jti,
                    recorded_cwd.as_deref(),
                );
                if let Some(jti) = &pending_jti
                    && let Some(pane) = policy::created_pane_id(&method, &result)
                {
                    state.bind_token(jti, pane);
                }
                if identity.role != Role::Admin {
                    policy::filter_result(&method, &mut result, &state, &identity.sub);
                }
                state.clone()
            };
            if matches!(method.as_str(), "pane.split" | "tab.create") {
                if let Err(error) = ctx.store.replace_state(&snapshot).await {
                    return protocol::error(&id, "internal", &error);
                }
                if let Some(jti) = &pending_jti
                    && let Some(pane) = policy::created_pane_id(&method, &result)
                    && let Err(error) = ctx.store.set_principal_pane(jti, pane).await
                {
                    return protocol::error(&id, "internal", &error);
                }
            }
            protocol::ok(&id, result)
        }
        Err(message) => protocol::error(&id, "upstream_error", &message),
    }
}

/// Replace the caller's `cwd` with the token's authoritative working
/// directory. A caller may repeat the claim but cannot change it.
fn enforce_cwd(
    identity: &Identity,
    params: &mut Value,
) -> Result<Option<String>, (String, String)> {
    let Some(claimed) = identity.cwd.as_deref() else {
        return Err((
            "missing_cwd".to_string(),
            "token has no cwd claim".to_string(),
        ));
    };
    let claimed =
        cwd::canonical_claim(claimed).map_err(|error| ("invalid_cwd".to_string(), error))?;
    if let Some(requested) = params.get("cwd").and_then(Value::as_str) {
        let requested =
            cwd::canonical(requested).map_err(|error| ("invalid_cwd".to_string(), error))?;
        if requested != claimed {
            return Err((
                "forbidden".to_string(),
                "cwd is fixed by the token".to_string(),
            ));
        }
    }
    params["cwd"] = json!(claimed);
    Ok(Some(claimed))
}

/// Replace the caller's `workspace_id` with the token's authoritative
/// workspace. A caller may repeat the claim but cannot change it.
fn enforce_workspace_id(
    identity: &Identity,
    params: &mut Value,
) -> Result<Option<String>, (String, String)> {
    let Some(claimed) = identity.workspace_id.as_deref() else {
        return Err((
            "missing_workspace".to_string(),
            "token has no workspace_id claim".to_string(),
        ));
    };
    if claimed.is_empty() {
        return Err((
            "invalid_workspace".to_string(),
            "token workspace_id is empty".to_string(),
        ));
    }
    if let Some(requested) = params.get("workspace_id").and_then(Value::as_str)
        && requested != claimed
    {
        return Err((
            "forbidden".to_string(),
            "workspace_id is fixed by the token".to_string(),
        ));
    }
    params["workspace_id"] = json!(claimed);
    Ok(Some(claimed.to_owned()))
}

/// Resolve an agent-name target to its pane and require ownership. Pane-id
/// targets are checked by the generic ownership block before this runs.
async fn check_agent_name_target(
    ctx: &Arc<Ctx>,
    identity: &Identity,
    target: &str,
) -> Result<(), (String, String)> {
    let result = upstream::request(
        &ctx.paths.upstream_socket,
        "agent.get",
        json!({ "target": target }),
        "resolve-agent",
    )
    .await
    .map_err(|_| {
        (
            "forbidden".to_string(),
            "agent target not found or not owned".to_string(),
        )
    })?;
    let pane = result
        .pointer("/agent/pane_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                "forbidden".to_string(),
                "agent target has no pane".to_string(),
            )
        })?
        .to_owned();
    let state = ctx.state.lock().await;
    if identity.pane_id.as_deref() != Some(pane.as_str()) && !state.owns_pane(&pane, &identity.sub)
    {
        return Err((
            "forbidden".to_string(),
            "agent target is not owned by caller".to_string(),
        ));
    }
    Ok(())
}

/// An `agent.start` target must be a pane the proxy created in the caller's
/// token-bound cwd. herdr's `agent.start` has no cwd parameter (0.9.5), so the
/// pane's shell cwd is what the agent inherits.
async fn check_agent_start_cwd(
    ctx: &Arc<Ctx>,
    identity: &Identity,
    params: &Value,
) -> Result<(), (String, String)> {
    let Some(claimed) = identity.cwd.as_deref() else {
        return Err((
            "missing_cwd".to_string(),
            "token has no cwd claim".to_string(),
        ));
    };
    let claimed =
        cwd::canonical_claim(claimed).map_err(|error| ("invalid_cwd".to_string(), error))?;
    let Some(pane) = policy::pane_id_param(params) else {
        return Err((
            "invalid_param".to_string(),
            "agent.start requires pane_id".to_string(),
        ));
    };
    let pane = pane.to_owned();
    let state = ctx.state.lock().await;
    if state.pane_cwd(&pane) != Some(claimed.as_str()) {
        return Err((
            "forbidden".to_string(),
            "pane was not created in the token cwd".to_string(),
        ));
    }
    Ok(())
}

fn string_array(params: &Value, key: &str) -> Vec<String> {
    params
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn clamp_exp(exp: Option<u64>, parent: Option<u64>, max_ttl: Option<u64>, now: u64) -> Option<u64> {
    let mut exp = exp;
    if let Some(parent) = parent {
        exp = Some(exp.map_or(parent, |exp| exp.min(parent)));
    }
    if let Some(max_ttl) = max_ttl {
        let cap = now.saturating_add(max_ttl);
        exp = Some(exp.map_or(cap, |exp| exp.min(cap)));
    }
    exp
}

async fn mint(
    ctx: &Arc<Ctx>,
    identity: &Identity,
    params: &Value,
) -> Result<Value, (String, String)> {
    let role = match params
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or("agent")
    {
        "agent" => Role::Agent,
        "orchestrator" => Role::Orchestrator,
        "admin" => Role::Admin,
        other => return Err(("invalid_param".into(), format!("unknown role `{other}`"))),
    };
    let grants = string_array(params, "grants");
    grants::validate(&grants).map_err(|error| ("invalid_grant".to_string(), error))?;
    if role != Role::Agent && !grants.is_empty() {
        return Err((
            "invalid_param".into(),
            "grants are only valid for agent tokens".into(),
        ));
    }
    let requested_ttl = params.get("ttl_s").and_then(Value::as_u64);
    let pane_id = params
        .get("pane_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if role != Role::Agent && pane_id.is_some() {
        return Err((
            "invalid_param".into(),
            "pane_id is only valid for agent tokens".into(),
        ));
    }
    let is_bootstrap = identity.jti == ctx.bootstrap_jti;

    // The bootstrap token is the operator: it may hand an agent token to an
    // existing pane even though bootstrap owns no TUI-created panes. Every
    // other non-admin minter must already own the pane. Ownership stays with
    // the operator; the agent reaches the pane through its `pane_id` claim.
    if let Some(pane) = &pane_id
        && identity.role != Role::Admin
        && !is_bootstrap
    {
        let state = ctx.state.lock().await;
        if !state.owns_pane(pane, &identity.sub) {
            return Err((
                "forbidden".into(),
                "pane_id is not owned by the minter".into(),
            ));
        }
    }

    let perm: Option<Perm> = params
        .get("perm")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| ("invalid_param".to_string(), format!("perm: {error}")))?;
    if role == Role::Agent && perm.is_some() {
        return Err((
            "invalid_param".into(),
            "perm is only valid for orchestrator tokens".into(),
        ));
    }
    if let Some(perm) = &perm
        && perm
            .agent_kinds
            .iter()
            .any(|kind| !policy::SANDBOXED_AGENT_KINDS.contains(&kind.as_str()))
    {
        return Err((
            "forbidden".into(),
            format!(
                "agent_kinds limited to {}",
                policy::SANDBOXED_AGENT_KINDS.join(", ")
            ),
        ));
    }

    match identity.role {
        Role::Admin => {}
        Role::Orchestrator if is_bootstrap => {
            // The bootstrap token is orchestrator-scoped: it may mint agent or
            // orchestrator tokens, but never admin tokens.
            if role == Role::Admin {
                return Err((
                    "forbidden".into(),
                    "bootstrap cannot mint admin tokens".into(),
                ));
            }
        }
        Role::Orchestrator => {
            if role != Role::Agent {
                return Err((
                    "forbidden".into(),
                    "orchestrator may only mint agent tokens".into(),
                ));
            }
            let allowed = identity
                .perm
                .as_ref()
                .map(|perm| perm.agent_grants.clone())
                .filter(|grants| !grants.is_empty())
                .unwrap_or_else(grants::default_orchestrator_grants);
            if !grants::is_subset(&grants, &allowed) {
                return Err((
                    "grant_not_allowed".into(),
                    format!("allowed grants: {}", allowed.join(", ")),
                ));
            }
        }
        Role::Agent => {
            return Err(("forbidden".into(), "agents cannot mint tokens".into()));
        }
    }

    // A child token inherits the minter's cwd. Orchestrators cannot widen or
    // replace it. The bootstrap token has no cwd of its own; it may set the
    // first orchestrator's cwd explicitly (required for an orchestrator).
    let cwd = if is_bootstrap {
        let cwd = params
            .get("cwd")
            .and_then(Value::as_str)
            .map(cwd::canonical)
            .transpose()
            .map_err(|error| ("invalid_cwd".to_string(), error))?;
        if role == Role::Orchestrator && cwd.is_none() {
            return Err((
                "invalid_cwd".into(),
                "bootstrap orchestrator tokens require cwd".into(),
            ));
        }
        cwd
    } else {
        match identity.role {
            Role::Admin => params
                .get("cwd")
                .and_then(Value::as_str)
                .map(cwd::canonical)
                .transpose()
                .map_err(|error| ("invalid_cwd".to_string(), error))?,
            Role::Orchestrator => {
                let inherited = identity
                    .cwd
                    .as_deref()
                    .map(cwd::canonical_claim)
                    .transpose()
                    .map_err(|error| ("invalid_cwd".to_string(), error))?;
                if let Some(requested) = params.get("cwd").and_then(Value::as_str) {
                    let requested = cwd::canonical(requested)
                        .map_err(|error| ("invalid_cwd".to_string(), error))?;
                    if inherited.as_deref() != Some(requested.as_str()) {
                        return Err((
                            "forbidden".to_string(),
                            "cwd is fixed by the token".to_string(),
                        ));
                    }
                }
                inherited
            }
            Role::Agent => None,
        }
    };

    // Workspace assignment follows the same rule as cwd: bootstrap/admin set
    // it, orchestrators only inherit it, and it is required for orchestrators.
    let requested_workspace = params
        .get("workspace_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    if params.get("workspace_id").is_some() && requested_workspace.is_none() {
        return Err((
            "invalid_workspace".into(),
            "workspace_id must be a non-empty string".into(),
        ));
    }
    let workspace_id = if is_bootstrap {
        if role == Role::Orchestrator && requested_workspace.is_none() {
            return Err((
                "invalid_workspace".into(),
                "bootstrap orchestrator tokens require workspace_id".into(),
            ));
        }
        requested_workspace
    } else {
        match identity.role {
            Role::Admin => requested_workspace,
            Role::Orchestrator => {
                let inherited = identity.workspace_id.clone();
                if let Some(requested) = &requested_workspace
                    && inherited.as_deref() != Some(requested.as_str())
                {
                    return Err((
                        "forbidden".to_string(),
                        "workspace_id is fixed by the token".to_string(),
                    ));
                }
                inherited
            }
            Role::Agent => None,
        }
    };

    let now = jwt::now();
    let max_ttl = ctx.cfg.max_token_ttl_s;
    let exp = requested_ttl
        .map(|ttl| now.saturating_add(ttl.min(max_ttl)))
        .or_else(|| {
            (role == Role::Agent).then(|| now.saturating_add(ctx.cfg.agent_ttl_s.min(max_ttl)))
        });
    let exp = clamp_exp(
        exp,
        identity.exp,
        identity.perm.as_ref().and_then(|perm| perm.mint_max_ttl_s),
        now,
    );

    let jti = jwt::random_id();
    // Never let the caller choose a bare `sub`: ownership checks compare sub
    // prefixes. A requested label becomes a suffix under the minter's sub.
    let sub = match params.get("sub").and_then(Value::as_str).map(str::trim) {
        Some(label) if !label.is_empty() => {
            format!("{}:{}:{}", identity.sub, &jti[..8], label)
        }
        _ => format!("{}:{}", identity.sub, &jti[..8]),
    };
    let claims = Claims {
        iss: jwt::ISS.into(),
        sub,
        jti: jti.clone(),
        iat: now,
        nbf: now,
        exp,
        role,
        pane_id: pane_id.clone(),
        cwd,
        workspace_id,
        grants: {
            let mut grants = grants;
            if role == Role::Agent && grants.is_empty() {
                grants.push("report_status".into());
            }
            grants
        },
        perm,
    };
    let token = jwt::mint(&ctx.keys, &claims).map_err(|error| ("internal".into(), error))?;

    {
        let snapshot = {
            let mut state = ctx.state.lock().await;
            state.tokens.insert(
                jti.clone(),
                crate::state::TokenEntry {
                    sub: identity.sub.clone(),
                    pane_id: pane_id.clone(),
                    exp,
                },
            );
            state.clone()
        };
        ctx.store
            .replace_state(&snapshot)
            .await
            .map_err(|error| ("internal".to_string(), error))?;
    }
    ctx.store
        .record_principal(&claims, Some((&identity.jti, &identity.sub)), now)
        .await
        .map_err(|error| ("internal".to_string(), error))?;
    if let Some(pane) = &pane_id {
        ctx.store
            .set_principal_pane(&jti, pane)
            .await
            .map_err(|error| ("internal".to_string(), error))?;
    }

    Ok(json!({
        "token": token,
        "jti": jti,
        "role": claims.role,
        "exp": exp,
    }))
}

async fn spawn(
    ctx: &Arc<Ctx>,
    identity: &Identity,
    params: &Value,
) -> Result<Value, (String, String)> {
    if identity.role == Role::Agent {
        return Err(("forbidden".into(), "agents cannot spawn agents".into()));
    }
    if params.get("perm").is_some() {
        return Err((
            "invalid_param".into(),
            "perm is not valid for agent tokens".into(),
        ));
    }
    let kind = params
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| ("invalid_param".to_string(), "kind is required".into()))?;
    let requested_kinds = identity
        .perm
        .as_ref()
        .map(|perm| perm.agent_kinds.clone())
        .filter(|kinds| !kinds.is_empty());
    let kinds: Vec<String> = match requested_kinds {
        Some(kinds) => kinds
            .into_iter()
            .filter(|kind| policy::SANDBOXED_AGENT_KINDS.contains(&kind.as_str()))
            .collect(),
        None => policy::SANDBOXED_AGENT_KINDS
            .iter()
            .map(|kind| (*kind).to_string())
            .collect(),
    };
    if !kinds.iter().any(|allowed| allowed == kind) {
        return Err((
            "forbidden".into(),
            format!(
                "allowed kinds: {}",
                policy::SANDBOXED_AGENT_KINDS.join(", ")
            ),
        ));
    }

    // The token's cwd is authoritative. Admin tokens without a cwd may pass
    // one explicitly; all other tokens are pinned to their own claim.
    let safe_cwd = match identity.cwd.as_deref() {
        Some(claimed) => {
            let claimed = cwd::canonical_claim(claimed)
                .map_err(|error| ("invalid_cwd".to_string(), error))?;
            if let Some(requested) = params.get("cwd").and_then(Value::as_str) {
                let requested = cwd::canonical(requested)
                    .map_err(|error| ("invalid_cwd".to_string(), error))?;
                if requested != claimed {
                    return Err((
                        "forbidden".to_string(),
                        "cwd is fixed by the token".to_string(),
                    ));
                }
            }
            Some(claimed)
        }
        None if identity.role == Role::Admin => {
            params.get("cwd").and_then(Value::as_str).map(str::to_owned)
        }
        None => {
            return Err((
                "missing_cwd".to_string(),
                "token has no cwd claim".to_string(),
            ));
        }
    };

    // The token's workspace is authoritative. Admin tokens without a workspace
    // may pass one explicitly; all other tokens are pinned to their claim.
    let safe_workspace = match identity.workspace_id.as_deref() {
        Some(claimed) if !claimed.is_empty() => {
            if let Some(requested) = params.get("workspace_id").and_then(Value::as_str)
                && requested != claimed
            {
                return Err((
                    "forbidden".to_string(),
                    "workspace_id is fixed by the token".to_string(),
                ));
            }
            Some(claimed.to_owned())
        }
        Some(_) => {
            return Err((
                "invalid_workspace".to_string(),
                "token workspace_id is empty".to_string(),
            ));
        }
        None if identity.role == Role::Admin => params
            .get("workspace_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        None => {
            return Err((
                "missing_workspace".to_string(),
                "token has no workspace_id claim".to_string(),
            ));
        }
    };

    let mut requested = string_array(params, "grants");
    if requested.is_empty() {
        requested.push("report_status".into());
    }
    grants::validate(&requested).map_err(|error| ("invalid_grant".to_string(), error))?;
    if identity.role == Role::Orchestrator {
        let allowed = identity
            .perm
            .as_ref()
            .map(|perm| perm.agent_grants.clone())
            .filter(|grants| !grants.is_empty())
            .unwrap_or_else(grants::default_orchestrator_grants);
        if !grants::is_subset(&requested, &allowed) {
            return Err((
                "grant_not_allowed".into(),
                format!("allowed grants: {}", allowed.join(", ")),
            ));
        }
    }

    let now = jwt::now();
    let ttl = params
        .get("ttl_s")
        .and_then(Value::as_u64)
        .unwrap_or(ctx.cfg.agent_ttl_s)
        .min(ctx.cfg.max_token_ttl_s);
    let exp = clamp_exp(
        Some(now.saturating_add(ttl)),
        identity.exp,
        identity.perm.as_ref().and_then(|perm| perm.mint_max_ttl_s),
        now,
    );
    let jti = jwt::random_id();
    let claims = Claims {
        iss: jwt::ISS.into(),
        sub: format!("{}:{}", identity.sub, &jti[..8]),
        jti: jti.clone(),
        iat: now,
        nbf: now,
        exp,
        role: Role::Agent,
        pane_id: None,
        cwd: safe_cwd.clone(),
        workspace_id: safe_workspace.clone(),
        grants: requested,
        perm: None,
    };
    let token = jwt::mint(&ctx.keys, &claims).map_err(|error| ("internal".into(), error))?;

    let mut tab_params = json!({
        "env": { "HERDR_AUTH_JWT": token },
        "focus": params.get("focus").cloned().unwrap_or(json!(false)),
    });
    if let Some(value) = &safe_cwd {
        tab_params["cwd"] = json!(value);
    }
    if let Some(value) = &safe_workspace {
        tab_params["workspace_id"] = json!(value);
    }
    if let Some(value) = params.get("label") {
        tab_params["label"] = value.clone();
    }

    let tab = upstream::request(
        &ctx.paths.upstream_socket,
        "tab.create",
        tab_params,
        "spawn-tab",
    )
    .await
    .map_err(|error| ("upstream_error".into(), error))?;
    let tab_id = tab
        .pointer("/tab/tab_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                "upstream_error".to_string(),
                "tab.create returned no tab_id".into(),
            )
        })?
        .to_owned();
    let pane_id = tab
        .pointer("/root_pane/pane_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                "upstream_error".to_string(),
                "tab.create returned no root pane".into(),
            )
        })?
        .to_owned();

    {
        let snapshot = {
            let mut state = ctx.state.lock().await;
            state.tokens.insert(
                jti.clone(),
                crate::state::TokenEntry {
                    sub: identity.sub.clone(),
                    pane_id: None,
                    exp,
                },
            );
            state.bind_token(&jti, &pane_id);
            state.record_tab(&tab_id, &identity.sub);
            state.record_pane(&pane_id, &identity.sub, Some(&jti), safe_cwd.as_deref());
            state.clone()
        };
        ctx.store
            .replace_state(&snapshot)
            .await
            .map_err(|error| ("internal".to_string(), error))?;
    }
    ctx.store
        .record_principal(&claims, Some((&identity.jti, &identity.sub)), now)
        .await
        .map_err(|error| ("internal".to_string(), error))?;
    ctx.store
        .set_principal_pane(&jti, &pane_id)
        .await
        .map_err(|error| ("internal".to_string(), error))?;

    // herdr 0.9.5's agent.start has no cwd parameter: the agent inherits the
    // root pane's cwd, which was created from `safe_cwd` above.
    let mut start = json!({ "kind": kind, "pane_id": pane_id });
    if let Some(name) = params.get("name") {
        start["name"] = name.clone();
    }
    if let Some(args) = params.get("args") {
        start["args"] = args.clone();
    }
    if let Some(timeout) = params.get("timeout_ms") {
        start["timeout_ms"] = timeout.clone();
    }

    match upstream::request(
        &ctx.paths.upstream_socket,
        "agent.start",
        start,
        "spawn-start",
    )
    .await
    {
        Ok(_) => Ok(json!({
            "tab_id": tab_id,
            "pane_id": pane_id,
            "agent": kind,
        })),
        Err(error) => {
            let _ = upstream::request(
                &ctx.paths.upstream_socket,
                "tab.close",
                json!({ "tab_id": tab_id }),
                "spawn-cleanup",
            )
            .await;
            let snapshot = {
                let mut state = ctx.state.lock().await;
                state.tokens.remove(&jti);
                state.panes.remove(&pane_id);
                state.tabs.remove(&tab_id);
                state.clone()
            };
            if let Err(error) = ctx.store.replace_state(&snapshot).await {
                eprintln!("herdr-auth-proxy: cleanup state: {error}");
            }
            Err(("agent_start_failed".into(), error))
        }
    }
}

async fn caller_principal(
    ctx: &Arc<Ctx>,
    identity: &Identity,
) -> Result<Principal, (String, String)> {
    ctx.store
        .principal_by_jti(&identity.jti)
        .await
        .map_err(internal)?
        .ok_or_else(|| {
            (
                "unauthorized".to_string(),
                "token has no recorded principal".to_string(),
            )
        })
}

fn internal(error: String) -> (String, String) {
    ("internal".to_string(), error)
}

fn require_str<'a>(params: &'a Value, key: &str) -> Result<&'a str, (String, String)> {
    params
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ("invalid_param".to_string(), format!("{key} is required")))
}

fn optional_str(params: &Value, key: &str) -> Option<String> {
    params
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

async fn resolve_message_target(
    ctx: &Arc<Ctx>,
    caller: &Principal,
    to: &str,
) -> Result<Principal, (String, String)> {
    if let Some(principal) = ctx
        .store
        .resolve_recipient(caller, to)
        .await
        .map_err(internal)?
    {
        return Ok(principal);
    }
    // Agent names are not principals; resolve them through herdr.
    if !to.contains(':')
        && to != "parent"
        && let Ok(result) = upstream::request(
            &ctx.paths.upstream_socket,
            "agent.get",
            json!({ "target": to }),
            "message-resolve",
        )
        .await
        && let Some(pane) = result.pointer("/agent/pane_id").and_then(Value::as_str)
        && let Some(principal) = ctx.store.principal_by_pane(pane).await.map_err(internal)?
    {
        return Ok(principal);
    }
    Err((
        "unknown_target".to_string(),
        "message target is not a known principal".to_string(),
    ))
}

async fn message_send(
    ctx: &Arc<Ctx>,
    identity: &Identity,
    params: &Value,
) -> Result<Value, (String, String)> {
    if params.get("from").is_some() {
        return Err((
            "invalid_param".to_string(),
            "`from` is set by the proxy".to_string(),
        ));
    }
    let caller = caller_principal(ctx, identity).await?;
    let to = require_str(params, "to")?;
    let body = params
        .get("body")
        .and_then(Value::as_str)
        .filter(|body| !body.trim().is_empty())
        .ok_or_else(|| ("invalid_param".to_string(), "body is required".to_string()))?;
    if body.len() > ctx.cfg.message_max_bytes {
        return Err((
            "message_too_large".to_string(),
            format!("body exceeds {} bytes", ctx.cfg.message_max_bytes),
        ));
    }
    let target = resolve_message_target(ctx, &caller, to).await?;
    let now = jwt::now();
    if !ctx
        .store
        .can_message(&caller, &target, now)
        .await
        .map_err(internal)?
    {
        return Err((
            "forbidden".to_string(),
            "target is not a parent, child, or granted peer".to_string(),
        ));
    }

    let ttl = params
        .get("ttl_s")
        .and_then(Value::as_u64)
        .unwrap_or(ctx.cfg.message_ttl_s)
        .min(ctx.cfg.message_ttl_s);
    let expires_at = (ttl > 0).then(|| (now + ttl) as i64);
    let message = NewMessage {
        to: target.clone(),
        body: body.to_string(),
        thread_id: optional_str(params, "thread_id"),
        reply_to: optional_str(params, "reply_to"),
        expires_at,
    };
    let id = ctx
        .store
        .send(&caller, &message, now)
        .await
        .map_err(internal)?;
    ctx.mail.notify(&target.jti).await;
    spawn_wakeup(ctx.clone(), target.clone(), id.clone(), now);

    Ok(json!({
        "id": id,
        "from_sub": caller.sub,
        "from_jti": caller.jti,
        "to_sub": target.sub,
        "to_jti": target.jti,
        "to_pane_id": target.pane_id,
        "created_at": now,
        "status": "queued",
        "wakeup": "notified",
    }))
}

async fn message_poll(
    ctx: &Arc<Ctx>,
    identity: &Identity,
    params: &Value,
) -> Result<Value, (String, String)> {
    let caller = caller_principal(ctx, identity).await?;
    let wait_ms = params
        .get("wait_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .min(ctx.cfg.message_poll_max_ms);
    let limit = params
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(10)
        .clamp(1, 100) as usize;
    ctx.store
        .mark_poll(&caller.jti, jwt::now())
        .await
        .map_err(internal)?;

    let deadline = tokio::time::Instant::now() + Duration::from_millis(wait_ms);
    let mut rx = ctx.mail.subscribe(&caller.jti).await;
    loop {
        let now = jwt::now();
        let messages = ctx
            .store
            .claim(&caller.jti, limit, ctx.cfg.message_claim_lease_s, now)
            .await
            .map_err(internal)?;
        if !messages.is_empty() {
            return Ok(json!({
                "messages": messages.iter().map(message_json).collect::<Vec<_>>(),
                "has_more": messages.len() == limit,
            }));
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Ok(json!({ "messages": [], "has_more": false, "timed_out": true }));
        }
        tokio::select! {
            _ = tokio::time::sleep(remaining) => {
                return Ok(json!({ "messages": [], "has_more": false, "timed_out": true }));
            }
            changed = rx.changed() => {
                if changed.is_err() {
                    return Ok(json!({ "messages": [], "has_more": false }));
                }
            }
        }
    }
}

async fn message_notify(
    ctx: &Arc<Ctx>,
    identity: &Identity,
    params: &Value,
) -> Result<Value, (String, String)> {
    let caller = caller_principal(ctx, identity).await?;
    let wait_ms = params
        .get("wait_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .min(ctx.cfg.message_poll_max_ms);
    let deadline = tokio::time::Instant::now() + Duration::from_millis(wait_ms);
    let mut rx = ctx.mail.subscribe(&caller.jti).await;
    loop {
        let now = jwt::now();
        let pending = ctx
            .store
            .pending_for(&caller.jti, now)
            .await
            .map_err(internal)?;
        if !pending.is_empty() {
            return Ok(json!({
                "pending": pending.len(),
                "messages": pending.iter().map(|message| json!({
                    "id": message.id,
                    "from_sub": message.from_sub,
                    "thread_id": message.thread_id,
                    "created_at": message.created_at,
                    "preview": preview(&message.body),
                })).collect::<Vec<_>>(),
            }));
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Ok(json!({ "pending": 0, "messages": [], "timed_out": true }));
        }
        tokio::select! {
            _ = tokio::time::sleep(remaining) => {
                return Ok(json!({ "pending": 0, "messages": [], "timed_out": true }));
            }
            changed = rx.changed() => {
                if changed.is_err() {
                    return Ok(json!({ "pending": 0, "messages": [] }));
                }
            }
        }
    }
}

async fn message_ack(
    ctx: &Arc<Ctx>,
    identity: &Identity,
    params: &Value,
) -> Result<Value, (String, String)> {
    let caller = caller_principal(ctx, identity).await?;
    let claim_id = require_str(params, "claim_id")?;
    let ids: Vec<String> = params
        .get("ids")
        .and_then(Value::as_array)
        .ok_or_else(|| ("invalid_param".to_string(), "ids is required".to_string()))?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .take(100)
        .collect();
    let acked = ctx
        .store
        .ack(&caller.jti, &ids, claim_id, jwt::now())
        .await
        .map_err(internal)?;
    Ok(json!({ "acked": acked }))
}

async fn message_status(
    ctx: &Arc<Ctx>,
    identity: &Identity,
    _params: &Value,
) -> Result<Value, (String, String)> {
    let caller = caller_principal(ctx, identity).await?;
    let now = jwt::now();
    let counts = ctx
        .store
        .counts_for(&caller.jti, now)
        .await
        .map_err(internal)?;
    let pending =
        counts.get("pending").copied().unwrap_or(0) + counts.get("claimed").copied().unwrap_or(0);
    let last_poll = caller.last_poll.unwrap_or(caller.created_at).max(0) as u64;
    let unresponsive = pending > 0 && now.saturating_sub(last_poll) > ctx.cfg.message_stale_s;
    Ok(json!({
        "jti": caller.jti,
        "sub": caller.sub,
        "counts": counts,
        "last_seen": caller.last_seen,
        "last_poll": caller.last_poll,
        "unresponsive": unresponsive,
    }))
}

async fn peer_grant(
    ctx: &Arc<Ctx>,
    identity: &Identity,
    params: &Value,
) -> Result<Value, (String, String)> {
    let caller = caller_principal(ctx, identity).await?;
    if caller.role == Role::Agent {
        return Err((
            "forbidden".to_string(),
            "agents cannot grant peer links".to_string(),
        ));
    }
    let a = require_str(params, "a")?;
    let b = require_str(params, "b")?;
    if a == b {
        return Err(("invalid_param".to_string(), "a and b differ".to_string()));
    }
    let a = resolve_message_target(ctx, &caller, a).await?;
    let b = resolve_message_target(ctx, &caller, b).await?;
    let parent = Some(caller.jti.as_str());
    if a.parent_jti.as_deref() != parent || b.parent_jti.as_deref() != parent {
        return Err((
            "forbidden".to_string(),
            "both targets must be direct children of the caller".to_string(),
        ));
    }
    let now = jwt::now();
    let expires_at = params
        .get("ttl_s")
        .and_then(Value::as_u64)
        .map(|ttl| (now + ttl) as i64);
    let grant_id = ctx
        .store
        .grant_peer(&caller.jti, &a.jti, &b.jti, expires_at, now)
        .await
        .map_err(internal)?;
    Ok(json!({
        "grant_id": grant_id,
        "a_jti": a.jti,
        "b_jti": b.jti,
        "expires_at": expires_at,
    }))
}

async fn peer_revoke(
    ctx: &Arc<Ctx>,
    identity: &Identity,
    params: &Value,
) -> Result<Value, (String, String)> {
    let caller = caller_principal(ctx, identity).await?;
    let grant_id = require_str(params, "grant_id")?;
    let revoked = ctx
        .store
        .revoke_peer(&caller.jti, grant_id, jwt::now())
        .await
        .map_err(internal)?;
    if !revoked {
        return Err((
            "not_found".to_string(),
            "grant not found or already revoked".to_string(),
        ));
    }
    Ok(json!({ "revoked": true }))
}

async fn peer_list(
    ctx: &Arc<Ctx>,
    identity: &Identity,
    _params: &Value,
) -> Result<Value, (String, String)> {
    let caller = caller_principal(ctx, identity).await?;
    let grants = ctx.store.list_peers(&caller.jti).await.map_err(internal)?;
    Ok(json!({ "grants": grants }))
}

fn preview(body: &str) -> String {
    const LIMIT: usize = 120;
    let mut preview: String = body.chars().take(LIMIT).collect();
    if body.chars().count() > LIMIT {
        preview.push('…');
    }
    preview
}

fn message_json(message: &Message) -> Value {
    json!({
        "id": message.id,
        "thread_id": message.thread_id,
        "reply_to": message.reply_to,
        "from_sub": message.from_sub,
        "from_jti": message.from_jti,
        "to_sub": message.to_sub,
        "to_jti": message.to_jti,
        "body": message.body,
        "created_at": message.created_at,
        "expires_at": message.expires_at,
        "status": message.status,
        "claim_id": message.claim_id,
        "claim_expires_at": message.claim_expires_at,
    })
}

const WAKEUP_PROMPT: &str =
    "[herdr-auth] unread messages are waiting. Call the message-poll tool now.";

/// Stage 2 fallback: prompt an idle agent if it did not poll after the
/// notification. Only a fixed proxy-generated string is ever sent.
fn spawn_wakeup(ctx: Arc<Ctx>, target: Principal, message_id: String, message_created_at: u64) {
    tokio::spawn(async move {
        let delay = Duration::from_secs(ctx.cfg.message_wakeup_after_s.max(1));
        let Some(pane) = target.pane_id.clone() else {
            return;
        };
        // Give the agent time to react to the MCP notification, then keep
        // checking until this message is claimed/acked, polled, or expires.
        loop {
            tokio::time::sleep(delay).await;
            let now = jwt::now();
            let pending = match ctx.store.pending_for(&target.jti, now).await {
                Ok(pending) => pending,
                Err(_) => return,
            };
            if !pending.iter().any(|message| message.id == message_id) {
                return;
            }
            let principal = match ctx.store.principal_by_jti(&target.jti).await {
                Ok(Some(principal)) => principal,
                _ => return,
            };
            if principal.last_poll.unwrap_or_default() as u64 >= message_created_at {
                return;
            }
            if !ctx
                .mail
                .may_wake(&target.jti, ctx.cfg.message_wakeup_min_interval_s, now)
                .await
            {
                continue;
            }
            if agent_status(&ctx, &pane).await.as_deref() != Some("idle") {
                continue;
            }
            if upstream::request(
                &ctx.paths.upstream_socket,
                "agent.prompt",
                json!({ "target": pane, "text": WAKEUP_PROMPT }),
                "message-wakeup",
            )
            .await
            .is_ok()
            {
                ctx.mail.mark_wake(&target.jti, now).await;
                return;
            }
        }
    });
}

async fn agent_status(ctx: &Arc<Ctx>, pane: &str) -> Option<String> {
    let result = upstream::request(
        &ctx.paths.upstream_socket,
        "agent.get",
        json!({ "target": pane }),
        "message-agent-status",
    )
    .await
    .ok()?;
    result
        .pointer("/agent/agent_status")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity(cwd: Option<String>) -> Identity {
        Identity {
            sub: "orch".into(),
            role: Role::Orchestrator,
            grants: Vec::new(),
            perm: None,
            pane_id: None,
            cwd,
            workspace_id: None,
            jti: "j1".into(),
            exp: None,
        }
    }

    fn temp_dir() -> String {
        let path = std::env::temp_dir().join(format!("hap-cwd-{}", jwt::random_id()));
        std::fs::create_dir_all(&path).unwrap();
        cwd::canonical(path.to_str().unwrap()).unwrap()
    }

    async fn test_ctx() -> Arc<Ctx> {
        let dir = std::env::temp_dir().join(format!("hap-server-{}", jwt::random_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let paths = Paths {
            config_dir: dir.clone(),
            state_dir: dir.clone(),
            auth_socket: dir.join("auth.sock"),
            upstream_socket: dir.join("herdr.sock"),
            state_file: dir.join("state.json"),
            state_db: dir.join("state.db"),
            pid_file: dir.join("proxy.pid"),
            log_file: dir.join("proxy.log"),
        };
        Arc::new(Ctx {
            cfg: config::Config::default(),
            paths,
            keys: keys::Keys::from_secret([9u8; 32]),
            state: Mutex::new(State::default()),
            store: crate::store::Store::in_memory().await.unwrap(),
            mail: Arc::new(MailHub::new()),
            bootstrap_jti: "bootstrap-jti".into(),
        })
    }

    fn bootstrap_identity() -> Identity {
        Identity {
            sub: "bootstrap".into(),
            role: Role::Orchestrator,
            grants: Vec::new(),
            perm: None,
            pane_id: None,
            cwd: None,
            workspace_id: None,
            jti: "bootstrap-jti".into(),
            exp: None,
        }
    }

    fn orchestrator_identity() -> Identity {
        Identity {
            sub: "orch".into(),
            role: Role::Orchestrator,
            grants: Vec::new(),
            perm: None,
            pane_id: None,
            cwd: None,
            workspace_id: None,
            jti: "orch-jti".into(),
            exp: None,
        }
    }

    fn agent_identity(pane: &str) -> Identity {
        Identity {
            sub: "orch:agent".into(),
            role: Role::Agent,
            grants: vec!["report_status".into(), "report_metadata".into()],
            perm: None,
            pane_id: Some(pane.into()),
            cwd: None,
            workspace_id: None,
            jti: "agent-jti".into(),
            exp: None,
        }
    }

    #[test]
    fn token_cwd_overrides_caller_cwd() {
        let dir = temp_dir();
        let identity = test_identity(Some(dir.clone()));
        let mut params = json!({});
        assert_eq!(
            enforce_cwd(&identity, &mut params).unwrap(),
            Some(dir.clone())
        );
        assert_eq!(params["cwd"], json!(dir));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn caller_cannot_change_cwd() {
        let dir = temp_dir();
        let identity = test_identity(Some(dir.clone()));
        let mut params = json!({"cwd": "/"});
        let (code, _) = enforce_cwd(&identity, &mut params).unwrap_err();
        assert_eq!(code, "forbidden");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_cwd_fails_closed() {
        let identity = test_identity(None);
        let mut params = json!({});
        let (code, _) = enforce_cwd(&identity, &mut params).unwrap_err();
        assert_eq!(code, "missing_cwd");
    }

    #[tokio::test]
    async fn mint_caps_requested_ttl() {
        let ctx = test_ctx().await;
        let identity = bootstrap_identity();
        let before = jwt::now();
        let result = mint(
            &ctx,
            &identity,
            &json!({"role": "agent", "ttl_s": 999_999_999u64}),
        )
        .await
        .unwrap();
        let exp = result["exp"].as_u64().unwrap();
        let expected = before.saturating_add(ctx.cfg.max_token_ttl_s);
        assert!(
            exp.abs_diff(expected) <= 2,
            "exp {exp} not capped at {expected}"
        );
    }

    #[tokio::test]
    async fn mint_rejects_perm_for_agent_tokens() {
        let ctx = test_ctx().await;
        let identity = bootstrap_identity();
        let (code, message) = mint(
            &ctx,
            &identity,
            &json!({"role": "agent", "perm": {"read_own_pane": true}}),
        )
        .await
        .unwrap_err();
        assert_eq!(code, "invalid_param");
        assert!(message.contains("perm"), "{message}");
    }

    #[tokio::test]
    async fn mint_rejects_grants_for_non_agent_tokens() {
        let ctx = test_ctx().await;
        let identity = bootstrap_identity();
        let (code, _) = mint(
            &ctx,
            &identity,
            &json!({
                "role": "orchestrator",
                "grants": ["report_status"],
                "cwd": "/tmp",
                "workspace_id": "w1",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(code, "invalid_param");
    }

    #[tokio::test]
    async fn default_orchestrator_can_grant_every_advertised_capability() {
        let ctx = test_ctx().await;
        let identity = bootstrap_identity();
        for grant in grants::GRANTABLE_AGENT_CAPABILITIES {
            let result = mint(
                &ctx,
                &identity,
                &json!({"role": "agent", "grants": [grant]}),
            )
            .await
            .unwrap();
            assert_eq!(result["role"], json!("agent"));
        }
    }

    #[tokio::test]
    async fn bootstrap_may_bind_an_agent_token_to_an_unowned_pane() {
        let ctx = test_ctx().await;
        let identity = bootstrap_identity();
        let result = mint(
            &ctx,
            &identity,
            &json!({"role": "agent", "pane_id": "w1:p99", "grants": ["wait_own_output"]}),
        )
        .await
        .unwrap();
        assert_eq!(result["role"], json!("agent"));
    }

    #[tokio::test]
    async fn non_bootstrap_orchestrator_cannot_bind_an_unowned_pane() {
        let ctx = test_ctx().await;
        let identity = orchestrator_identity();
        let (code, _) = mint(
            &ctx,
            &identity,
            &json!({"role": "agent", "pane_id": "w1:p99"}),
        )
        .await
        .unwrap_err();
        assert_eq!(code, "forbidden");
    }

    #[test]
    fn agent_wait_target_is_forced_to_the_claim() {
        let identity = agent_identity("w1:p8");
        let mut params = json!({"target": "w1:p9"});
        let (code, _) = enforce_agent_params(&identity, "agent.wait", &mut params).unwrap_err();
        assert_eq!(code, "forbidden");

        let mut params = json!({});
        enforce_agent_params(&identity, "agent.wait", &mut params).unwrap();
        assert_eq!(params["target"], json!("w1:p8"));
    }

    #[test]
    fn agent_foreign_pane_is_rejected() {
        let identity = agent_identity("w1:p8");
        let mut params = json!({"pane_id": "w1:p9"});
        let (code, _) =
            enforce_agent_params(&identity, "pane.report_agent", &mut params).unwrap_err();
        assert_eq!(code, "forbidden");
    }

    #[test]
    fn agent_pane_and_reporting_identity_are_forced() {
        let identity = agent_identity("w1:p8");
        let mut params = json!({"target_pane_id": "w1:p8"});
        enforce_agent_params(&identity, "pane.report_agent", &mut params).unwrap();
        assert_eq!(params["pane_id"], json!("w1:p8"));
        assert!(params.get("target_pane_id").is_none());
        assert_eq!(params["agent"], json!("opencode"));
        assert_eq!(params["source"], json!("herdr:opencode"));
    }

    #[test]
    fn agent_cannot_spoof_agent_identity() {
        let identity = agent_identity("w1:p8");
        let mut params = json!({"agent": "totally-bogus"});
        let (code, _) =
            enforce_agent_params(&identity, "pane.report_agent", &mut params).unwrap_err();
        assert_eq!(code, "forbidden");
    }

    #[test]
    fn agent_cannot_set_resume_argv() {
        let identity = agent_identity("w1:p8");
        let mut params = json!({"resume_argv": ["sh", "-c", "id"]});
        let (code, _) =
            enforce_agent_params(&identity, "pane.report_agent", &mut params).unwrap_err();
        assert_eq!(code, "forbidden");
    }

    #[tokio::test]
    async fn dispatch_rejects_a_foreign_pane_before_forwarding() {
        let ctx = test_ctx().await;
        let identity = agent_identity("w1:p8");
        let request = json!({
            "id": "1",
            "method": "pane.report_agent",
            "params": {
                "pane_id": "w1:p9",
                "agent": "opencode",
                "source": "herdr:opencode",
                "state": "idle",
            },
        });
        let response: Value = serde_json::from_str(&dispatch(&ctx, &identity, &request).await)
            .expect("valid response");
        assert_eq!(response["error"]["code"], json!("forbidden"));
    }

    #[tokio::test]
    async fn dispatch_rejects_agent_identity_spoofing() {
        let ctx = test_ctx().await;
        let identity = agent_identity("w1:p8");
        let request = json!({
            "id": "1",
            "method": "pane.report_agent",
            "params": {
                "pane_id": "w1:p8",
                "agent": "totally-bogus",
                "source": "herdr:opencode",
                "state": "idle",
            },
        });
        let response: Value = serde_json::from_str(&dispatch(&ctx, &identity, &request).await)
            .expect("valid response");
        assert_eq!(response["error"]["code"], json!("forbidden"));
    }

    fn message_claims(jti: &str, sub: &str, role: Role) -> Claims {
        Claims {
            iss: jwt::ISS.into(),
            sub: sub.into(),
            jti: jti.into(),
            iat: jwt::now(),
            nbf: jwt::now(),
            exp: None,
            role,
            pane_id: None,
            cwd: None,
            workspace_id: None,
            grants: Vec::new(),
            perm: None,
        }
    }

    fn message_identity(claims: &Claims) -> Identity {
        Identity {
            sub: claims.sub.clone(),
            role: claims.role,
            grants: claims.grants.clone(),
            perm: claims.perm.clone(),
            pane_id: claims.pane_id.clone(),
            cwd: claims.cwd.clone(),
            workspace_id: claims.workspace_id.clone(),
            jti: claims.jti.clone(),
            exp: claims.exp,
        }
    }

    async fn seed(ctx: &Arc<Ctx>, claims: &Claims, parent: Option<(&str, &str)>) {
        ctx.store
            .record_principal(claims, parent, jwt::now())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn parent_and_child_exchange_a_message() {
        let ctx = test_ctx().await;
        let parent = message_claims("p", "orch", Role::Orchestrator);
        let child = message_claims("c", "orch:c", Role::Agent);
        seed(&ctx, &parent, None).await;
        seed(&ctx, &child, Some(("p", "orch"))).await;

        let parent_identity = message_identity(&parent);
        let child_identity = message_identity(&child);
        let sent = message_send(
            &ctx,
            &parent_identity,
            &json!({"to": "orch:c", "body": " review this\n", "thread_id": "t1"}),
        )
        .await
        .unwrap();
        let id = sent["id"].as_str().unwrap().to_string();

        let polled = message_poll(&ctx, &child_identity, &json!({"wait_ms": 0}))
            .await
            .unwrap();
        let messages = polled["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["body"], json!(" review this\n"));
        let claim = messages[0]["claim_id"].as_str().unwrap();
        let acked = message_ack(
            &ctx,
            &child_identity,
            &json!({"ids": [id], "claim_id": claim}),
        )
        .await
        .unwrap();
        assert_eq!(acked["acked"], json!(1));

        // The child can reply to its parent without knowing the parent's jti.
        message_send(
            &ctx,
            &child_identity,
            &json!({"to": "parent", "body": "done", "reply_to": messages[0]["id"]}),
        )
        .await
        .unwrap();
        let reply = message_poll(&ctx, &parent_identity, &json!({"wait_ms": 0}))
            .await
            .unwrap();
        assert_eq!(reply["messages"][0]["body"], json!("done"));
    }

    #[tokio::test]
    async fn siblings_need_a_parent_grant() {
        let ctx = test_ctx().await;
        let parent = message_claims("p", "orch", Role::Orchestrator);
        let a = message_claims("a", "orch:a", Role::Agent);
        let b = message_claims("b", "orch:b", Role::Agent);
        seed(&ctx, &parent, None).await;
        seed(&ctx, &a, Some(("p", "orch"))).await;
        seed(&ctx, &b, Some(("p", "orch"))).await;
        let a_identity = message_identity(&a);
        let b_identity = message_identity(&b);
        let parent_identity = message_identity(&parent);

        let (code, _) = message_send(&ctx, &a_identity, &json!({"to": "orch:b", "body": "hi"}))
            .await
            .unwrap_err();
        assert_eq!(code, "forbidden");

        peer_grant(
            &ctx,
            &parent_identity,
            &json!({"a": "orch:a", "b": "orch:b"}),
        )
        .await
        .unwrap();
        message_send(&ctx, &a_identity, &json!({"to": "orch:b", "body": "hi"}))
            .await
            .unwrap();
        let polled = message_poll(&ctx, &b_identity, &json!({"wait_ms": 0}))
            .await
            .unwrap();
        assert_eq!(polled["messages"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn forged_from_is_rejected() {
        let ctx = test_ctx().await;
        let parent = message_claims("p", "orch", Role::Orchestrator);
        seed(&ctx, &parent, None).await;
        let identity = message_identity(&parent);
        let (code, _) = message_send(
            &ctx,
            &identity,
            &json!({"to": "parent", "body": "x", "from": "someone-else"}),
        )
        .await
        .unwrap_err();
        assert_eq!(code, "invalid_param");
    }

    #[tokio::test]
    async fn orchestrator_cannot_use_raw_read_or_prompt() {
        let ctx = test_ctx().await;
        let identity = orchestrator_identity();
        for (method, params) in [
            ("agent.prompt", json!({"target": "worker", "text": "x"})),
            ("pane.read", json!({"pane_id": "w1:p1"})),
        ] {
            let request = json!({"id": "1", "method": method, "params": params});
            let response: Value = serde_json::from_str(&dispatch(&ctx, &identity, &request).await)
                .expect("valid response");
            assert_eq!(response["error"]["code"], json!("forbidden"), "{method}");
        }
    }

    #[tokio::test]
    async fn admin_read_is_not_policy_denied() {
        let ctx = test_ctx().await;
        let identity = Identity {
            sub: "root".into(),
            role: Role::Admin,
            grants: Vec::new(),
            perm: None,
            pane_id: None,
            cwd: None,
            workspace_id: None,
            jti: "root".into(),
            exp: None,
        };
        let request = json!({"id": "1", "method": "pane.read", "params": {"pane_id": "w1:p1"}});
        let response: Value = serde_json::from_str(&dispatch(&ctx, &identity, &request).await)
            .expect("valid response");
        assert_eq!(response["error"]["code"], json!("upstream_error"));
    }
}
