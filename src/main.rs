//! herdr-auth-proxy server / lifecycle CLI.
//!
//! Token minting is handled by the `herdr-auth` client (`herdr-auth token
//! mint`); this binary manages the proxy session only.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use herdr_auth_proxy::{config, lifecycle, server};

#[derive(Debug, Parser)]
#[command(
    name = "herdr-auth-proxy",
    version,
    about = "Session-managed JWT proxy in front of herdr's socket API"
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
