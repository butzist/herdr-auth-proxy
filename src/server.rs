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
use crate::{config, cwd, environ, grants, jwt, keys, policy, protocol, state::State, upstream};

struct Ctx {
    cfg: config::Config,
    paths: Paths,
    keys: keys::Keys,
    state: Mutex<State>,
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
    let mut state = State::load(&paths.state_file);
    state.prune(jwt::now());
    let ctx = Arc::new(Ctx {
        cfg,
        paths: paths.clone(),
        keys,
        state: Mutex::new(state),
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
        let identity = identity_from_claims(&ctx, claims).await;
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
        identity_from_claims(&ctx, claims).await
    };

    let response = dispatch(&ctx, &identity, &request).await;
    protocol::write_line(&mut write_half, &response)
        .await
        .map_err(|error| format!("write response: {error}"))?;
    Ok(())
}

async fn identity_from_claims(ctx: &Ctx, claims: Claims) -> Identity {
    let pane_id = match claims.pane_id.clone() {
        Some(pane) => Some(pane),
        None => {
            let state = ctx.state.lock().await;
            state.pane_of_token(&claims.jti)
        }
    };
    Identity {
        sub: claims.sub,
        role: claims.role,
        grants: claims.grants,
        perm: claims.perm,
        pane_id,
        cwd: claims.cwd,
        workspace_id: claims.workspace_id,
        jti: claims.jti,
        exp: claims.exp,
    }
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
            })),
            "auth.token.mint" => mint(ctx, identity, &params).await,
            "auth.agent.spawn" => spawn(ctx, identity, &params).await,
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
            {
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
                if matches!(method.as_str(), "pane.split" | "tab.create") {
                    let _ = state.save(&ctx.paths.state_file);
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
        let mut state = ctx.state.lock().await;
        state.tokens.insert(
            jti.clone(),
            crate::state::TokenEntry {
                sub: identity.sub.clone(),
                pane_id,
                exp,
            },
        );
        let _ = state.save(&ctx.paths.state_file);
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
        let _ = state.save(&ctx.paths.state_file);
    }

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
            let mut state = ctx.state.lock().await;
            state.tokens.remove(&jti);
            state.panes.remove(&pane_id);
            state.tabs.remove(&tab_id);
            let _ = state.save(&ctx.paths.state_file);
            Err(("agent_start_failed".into(), error))
        }
    }
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

    fn test_ctx() -> Arc<Ctx> {
        let dir = std::env::temp_dir().join(format!("hap-server-{}", jwt::random_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let paths = Paths {
            config_dir: dir.clone(),
            state_dir: dir.clone(),
            auth_socket: dir.join("auth.sock"),
            upstream_socket: dir.join("herdr.sock"),
            state_file: dir.join("state.json"),
            pid_file: dir.join("proxy.pid"),
            log_file: dir.join("proxy.log"),
        };
        Arc::new(Ctx {
            cfg: config::Config::default(),
            paths,
            keys: keys::Keys::from_secret([9u8; 32]),
            state: Mutex::new(State::default()),
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
        let ctx = test_ctx();
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
        let ctx = test_ctx();
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
        let ctx = test_ctx();
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
        let ctx = test_ctx();
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
        let ctx = test_ctx();
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
        let ctx = test_ctx();
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
        let ctx = test_ctx();
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
        let ctx = test_ctx();
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
}
