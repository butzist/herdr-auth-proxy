//! herdr-auth-proxy: JWT-authenticating, permission-filtering proxy in front of
//! herdr's JSON API socket. See ARCHITECTURE.md.

#![recursion_limit = "512"]

pub mod client;
pub mod config;
pub mod cwd;
pub mod environ;
pub mod grants;
pub mod jwt;
pub mod keys;
pub mod lifecycle;
pub mod mail;
pub mod mcp;
pub mod policy;
pub mod protocol;
pub mod server;
pub mod state;
pub mod store;
pub mod upstream;
pub mod waits;
