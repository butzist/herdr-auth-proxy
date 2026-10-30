//! herdr-auth-proxy server / lifecycle CLI.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use herdr_auth_proxy::jwt::{Claims, Perm, Role};
use herdr_auth_proxy::{config, grants, jwt, keys, lifecycle, server};

#[derive(Debug, Parser)]
#[command(
    name = "herdr-auth-proxy",
    version,
    about = "JWT-authenticating proxy for herdr's socket API"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the proxy in the foreground (started detached by `wrap`)
    Serve,
    /// Ensure the proxy is running, then exec the given command (e.g. herdr)
    Wrap {
        #[arg(last = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Mint a token locally (bootstrap; requires access to the private key)
    Mint {
        #[arg(long, default_value = "admin")]
        role: String,
        #[arg(long)]
        sub: Option<String>,
        #[arg(long)]
        ttl_s: Option<u64>,
        #[arg(long)]
        pane: Option<String>,
        /// Grant (agent tokens): report_status, report_metadata, read_own_pane,
        /// wait_own_output
        #[arg(long = "grant")]
        grants: Vec<String>,
        /// Permission object as JSON (orchestrator tokens)
        #[arg(long)]
        perm: Option<String>,
    },
    /// Generate the Ed25519 keypair if it does not exist
    Keygen,
    /// Stop the running proxy
    Stop,
    /// Show proxy status
    Status,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("herdr-auth-proxy: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("tokio runtime: {error}"))?;
            runtime.block_on(server::run())
        }
        Command::Wrap { command } => lifecycle::wrap(&command),
        Command::Mint {
            role,
            sub,
            ttl_s,
            pane,
            grants,
            perm,
        } => mint(&role, sub, ttl_s, pane, grants, perm),
        Command::Keygen => {
            let (_, paths) = config::load()?;
            let keys = keys::KeyPair::load_or_create(&paths)?;
            println!("{}", keys.public_key_b64());
            Ok(())
        }
        Command::Stop => {
            let (_, paths) = config::load()?;
            lifecycle::stop(&paths)
        }
        Command::Status => {
            let (_, paths) = config::load()?;
            println!("{}", lifecycle::status(&paths));
            Ok(())
        }
    }
}

fn mint(
    role: &str,
    sub: Option<String>,
    ttl_s: Option<u64>,
    pane: Option<String>,
    requested_grants: Vec<String>,
    perm: Option<String>,
) -> Result<(), String> {
    let (cfg, paths) = config::load()?;
    let keys = keys::KeyPair::load_or_create(&paths)?;
    let role = match role {
        "agent" => Role::Agent,
        "orchestrator" => Role::Orchestrator,
        "admin" => Role::Admin,
        other => return Err(format!("unknown role `{other}`")),
    };
    grants::validate(&requested_grants)?;

    let now = jwt::now();
    let exp = ttl_s
        .map(|ttl| now + ttl)
        .or_else(|| (role == Role::Agent).then_some(now + cfg.agent_ttl_s));
    let jti = jwt::random_id();
    let sub = sub.unwrap_or_else(|| format!("{}:{}", role.as_str(), &jti[..8]));
    let perm: Option<Perm> = perm
        .map(|text| serde_json::from_str(&text))
        .transpose()
        .map_err(|error| format!("perm: {error}"))?;

    let claims = Claims {
        iss: jwt::ISS.into(),
        sub,
        jti,
        iat: now,
        nbf: now,
        exp,
        role,
        pane_id: pane,
        grants: requested_grants,
        perm,
    };
    let token = jwt::mint(&keys, &claims)?;
    println!("{token}");
    Ok(())
}
