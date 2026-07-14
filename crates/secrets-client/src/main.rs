//! Secrets Manager client CLI entrypoint.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use secrets_client::api::Api;
use secrets_client::cli::{Cli, Command, TokenCmd};
use secrets_client::{commands, config};

fn dispatch(cli: Cli) -> Result<i32> {
    let cfg = config::load()?;
    let no_cache = cli.command.no_cache();
    let api = if no_cache {
        Api::new_no_cache(&cfg)
    } else {
        Api::new(&cfg)
    };

    match cli.command {
        Command::Run {
            project, command, ..
        } => commands::run(&api, &project, &command),
        Command::Get { project, key, .. } => commands::get(&api, &project, &key),
        Command::Set { project, key } => commands::set(&api, &project, &key),
        Command::List { project, .. } => commands::list(&api, &project),
        Command::Export {
            project, format, ..
        } => commands::export(&api, &project, &format),
        Command::Token { cmd } => match cmd {
            TokenCmd::Create {
                name,
                project,
                ttl_days,
                no_expiry,
            } => commands::token_create(
                &api,
                &name,
                project.as_deref(),
                (!no_expiry).then_some(ttl_days),
                no_expiry,
            ),
            TokenCmd::Revoke { name } => commands::token_revoke(&api, &name),
            TokenCmd::List => commands::token_list(&api),
        },
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
