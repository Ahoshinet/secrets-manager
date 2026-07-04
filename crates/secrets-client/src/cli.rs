//! Command-line interface definition.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "secrets",
    about = "Fetch secrets and inject them into processes without writing .env to disk",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Fetch secrets and run a command with them injected into its env.
    ///
    /// Example: `secrets run --project cdn -- go run ./cmd/server`
    Run {
        #[arg(long)]
        project: String,
        /// Disable offline cache reads/writes for this invocation.
        #[arg(long)]
        no_cache: bool,
        /// The command to execute, given after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Print a single secret value to stdout.
    Get {
        #[arg(long)]
        project: String,
        /// Disable offline cache reads/writes for this invocation.
        #[arg(long)]
        no_cache: bool,
        key: String,
    },
    /// Set a secret. The value is read from stdin or an interactive
    /// hidden prompt — never from argv (which would leak via `ps`).
    Set {
        #[arg(long)]
        project: String,
        key: String,
    },
    /// List secret key names (values are never shown).
    List {
        #[arg(long)]
        project: String,
        /// Disable offline cache reads/writes for this invocation.
        #[arg(long)]
        no_cache: bool,
    },
    /// Print secrets in dotenv format to stdout (explicit opt-in).
    Export {
        #[arg(long)]
        project: String,
        /// Disable offline cache reads/writes for this invocation.
        #[arg(long)]
        no_cache: bool,
        #[arg(long, default_value = "dotenv")]
        format: String,
    },
}

impl Command {
    pub fn no_cache(&self) -> bool {
        match self {
            Command::Run { no_cache, .. }
            | Command::Get { no_cache, .. }
            | Command::List { no_cache, .. }
            | Command::Export { no_cache, .. } => *no_cache,
            Command::Set { .. } => false,
        }
    }
}
