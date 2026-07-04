//! Secrets Manager server binary entrypoint.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    match secrets_server::commands::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Print the error chain. Errors in this codebase are constructed
            // to never contain secret material.
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
