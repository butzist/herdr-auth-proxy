//! The proxy server: accept, authenticate, filter, forward.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::BufReader;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, watch};

use crate::config::Paths;
use crate::jwt::{Claims, Perm, Role};
use crate::{config, environ, grants, jwt, keys, policy, protocol, state::State, upstream};

struct Ctx {
    cfg: config::Config,
    paths: Paths,
    keys: keys::KeyPair,
    state: Mutex<State>,
}

struct Identity {
    sub: String,
    role: Role,
    grants: Vec<String>,
    perm: Option<Perm>,
    pane_id: Option<String>,
    jti: String,
    exp: Option<u64>,
}

pub async fn run() -> Result<(), String> {
    let (cfg, paths) = config::load()?;
    let keys = keys::KeyPair::load_or_create(&paths)?;
    let mut state = State::load(&paths.state_file);
    state.prune(jwt::now());
    let ctx = Arc::new(Ctx {
        cfg,
        paths: paths.clone(),
        keys,
        state: Mutex::new(state),
    });

    prepare_socket(&paths).await?;
    let listener = UnixListener::bind(&paths.auth_socket)
        .map_err(|error| format!("bind {}: {error}", paths.auth_socket.display()))?;
    let _ = std::fs::set_permissions(&paths.auth_socket, std::fs::Permissions::from_mode(0o666));
    write_pid(&paths)?;
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
        jti: claims.jti,
        exp: claims.exp,
    }
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

    if identity.role == Role::Agent {
        let Some(pane) = identity.pane_id.as_deref() else {
            return protocol::error(&id, "forbidden", "agent token is not bound to a pane");
        };
        if matches!(
            method.as_str(),
            "pane.report_agent"
                | "pane.report_agent_session"
                | "pane.report_metadata"
                | "pane.get"
                | "pane.read"
                | "pane.wait_for_output"
        ) {
            params["pane_id"] = json!(pane);
        }
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
            .unwrap_or_else(|| vec!["opencode".to_string()]);
        if !allowed.iter().any(|allowed| allowed == kind) {
            return protocol::error(&id, "forbidden", "agent kind not allowed");
        }
    }

    // Env authority: for non-admin pane creation the proxy builds the env and
    // injects a pending pane token. Caller env is discarded (no PATH/LD_* games).
    let mut pending_jti: Option<String> = None;
    if identity.role != Role::Admin && matches!(method.as_str(), "pane.split" | "tab.create") {
        let jti = jwt::random_id();
        let now = jwt::now();
        let exp = clamp_exp(
            Some(now + ctx.cfg.agent_ttl_s),
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
                    sub: claims.sub,
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
                policy::record_created(&method, &result, &mut state, &identity.sub, &identity.jti);
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
        exp = Some(exp.map_or(now + max_ttl, |exp| exp.min(now + max_ttl)));
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
    let requested_ttl = params.get("ttl_s").and_then(Value::as_u64);
    let pane_id = params
        .get("pane_id")
        .and_then(Value::as_str)
        .map(str::to_owned);

    match identity.role {
        Role::Admin => {}
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
                .unwrap_or_else(|| vec!["report_status".to_string()]);
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

    let now = jwt::now();
    let exp = requested_ttl
        .map(|ttl| now + ttl)
        .or_else(|| (role == Role::Agent).then_some(now + ctx.cfg.agent_ttl_s));
    let exp = clamp_exp(
        exp,
        identity.exp,
        identity.perm.as_ref().and_then(|perm| perm.mint_max_ttl_s),
        now,
    );

    let jti = jwt::random_id();
    let sub = params
        .get("sub")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{}:{}", identity.sub, &jti[..8]));
    let claims = Claims {
        iss: jwt::ISS.into(),
        sub,
        jti: jti.clone(),
        iat: now,
        nbf: now,
        exp,
        role,
        pane_id: pane_id.clone(),
        grants: {
            let mut grants = grants;
            if role == Role::Agent && grants.is_empty() {
                grants.push("report_status".into());
            }
            grants
        },
        perm: params
            .get("perm")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| ("invalid_param".to_string(), format!("perm: {error}")))?,
    };
    let token = jwt::mint(&ctx.keys, &claims).map_err(|error| ("internal".into(), error))?;

    {
        let mut state = ctx.state.lock().await;
        state.tokens.insert(
            jti.clone(),
            crate::state::TokenEntry {
                sub: claims.sub.clone(),
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
    let kind = params
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| ("invalid_param".to_string(), "kind is required".into()))?;
    let kinds = identity
        .perm
        .as_ref()
        .map(|perm| perm.agent_kinds.clone())
        .filter(|kinds| !kinds.is_empty())
        .unwrap_or_else(|| vec!["opencode".to_string()]);
    if !kinds.iter().any(|allowed| allowed == kind) {
        return Err((
            "forbidden".into(),
            format!("allowed kinds: {}", kinds.join(", ")),
        ));
    }

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
            .unwrap_or_else(|| vec!["report_status".to_string()]);
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
        .unwrap_or(ctx.cfg.agent_ttl_s);
    let exp = clamp_exp(
        Some(now + ttl),
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
        grants: requested,
        perm: None,
    };
    let token = jwt::mint(&ctx.keys, &claims).map_err(|error| ("internal".into(), error))?;

    let mut tab_params = json!({
        "env": { "HERDR_AUTH_JWT": token },
        "focus": params.get("focus").cloned().unwrap_or(json!(false)),
    });
    for key in ["workspace_id", "cwd", "label"] {
        if let Some(value) = params.get(key) {
            tab_params[key] = value.clone();
        }
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
                sub: claims.sub.clone(),
                pane_id: None,
                exp,
            },
        );
        state.bind_token(&jti, &pane_id);
        state.record_tab(&tab_id, &identity.sub);
        state.record_pane(&pane_id, &identity.sub, Some(&jti));
        let _ = state.save(&ctx.paths.state_file);
    }

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
