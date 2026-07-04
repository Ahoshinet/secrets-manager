//! Implementations of the client subcommands.

use std::io::{IsTerminal, Read, Write};
use std::process::Command;

use anyhow::{bail, Context, Result};
use secrecy::{ExposeSecret, SecretString};

use crate::api::{Api, SecretMap};

/// `secrets run` — fetch secrets, inject into the child env, execute.
///
/// The child inherits the parent environment plus the fetched secrets.
/// We never call `std::env::set_var`, so the parent process environment is
/// never polluted. Nothing is written to disk.
pub fn run(api: &Api, project: &str, command: &[String]) -> Result<i32> {
    if command.is_empty() {
        bail!("no command given after `--`");
    }
    let secrets = api.get_secrets(project)?;
    let mut cmd = build_command(command, &secrets);

    #[cfg(unix)]
    {
        // Replace the current process image (execvp semantics).
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        Err(anyhow::anyhow!("failed to exec `{}`: {err}", command[0]))
    }

    #[cfg(not(unix))]
    {
        let status = cmd
            .status()
            .with_context(|| format!("failed to run `{}`", command[0]))?;
        Ok(status.code().unwrap_or(1))
    }
}

/// Build the child `Command` with secrets injected as environment
/// variables. Exposed for testing env-injection behavior.
pub fn build_command(command: &[String], secrets: &SecretMap) -> Command {
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);
    for (k, v) in secrets {
        cmd.env(k, v.expose_secret());
    }
    cmd
}

/// `secrets get` — print one value to stdout.
pub fn get(api: &Api, project: &str, key: &str) -> Result<i32> {
    let secrets = api.get_secrets(project)?;
    match secrets.get(key) {
        Some(value) => {
            let mut out = std::io::stdout();
            out.write_all(value.expose_secret().as_bytes())?;
            out.write_all(b"\n")?;
            out.flush()?;
            Ok(0)
        }
        None => bail!("key not found: {key}"),
    }
}

/// `secrets list` — print key names only.
pub fn list(api: &Api, project: &str) -> Result<i32> {
    let secrets = api.get_secrets(project)?;
    for key in secrets.keys() {
        println!("{key}");
    }
    Ok(0)
}

/// `secrets export` — print dotenv to stdout (explicit opt-in only).
pub fn export(api: &Api, project: &str, format: &str) -> Result<i32> {
    if format != "dotenv" {
        bail!("unsupported export format: {format} (only 'dotenv' is supported)");
    }
    let secrets = api.get_secrets(project)?;
    let mut out = String::new();
    for (k, v) in &secrets {
        out.push_str(k);
        out.push('=');
        out.push_str(&dotenv_value(v.expose_secret()));
        out.push('\n');
    }
    print!("{out}");
    std::io::stdout().flush()?;
    Ok(0)
}

/// `secrets set` — read a value from stdin/prompt and store it.
pub fn set(api: &Api, project: &str, key: &str) -> Result<i32> {
    let value = read_secret_value()?;
    api.set_secret(project, key, &value)?;
    eprintln!("set `{key}` in project `{project}`");
    Ok(0)
}

/// Read a secret value without exposing it on the command line.
/// Interactive terminal -> hidden prompt; piped stdin -> read to EOF.
fn read_secret_value() -> Result<SecretString> {
    if std::io::stdin().is_terminal() {
        let entered =
            rpassword::prompt_password("Value: ").context("failed to read value from terminal")?;
        Ok(SecretString::from(entered))
    } else {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read value from stdin")?;
        // Strip a single trailing newline (common with `echo | secrets set`).
        if buf.ends_with('\n') {
            buf.pop();
            if buf.ends_with('\r') {
                buf.pop();
            }
        }
        if buf.is_empty() {
            bail!("empty value");
        }
        Ok(SecretString::from(buf))
    }
}

/// Format a value for a dotenv line. Bare when it only contains safe
/// characters, otherwise double-quoted with escaping.
fn dotenv_value(value: &str) -> String {
    let safe = !value.is_empty()
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/' | b':' | b'@')
        });
    if safe {
        value.to_string()
    } else {
        let mut s = String::with_capacity(value.len() + 2);
        s.push('"');
        for c in value.chars() {
            match c {
                '\\' => s.push_str("\\\\"),
                '"' => s.push_str("\\\""),
                '\n' => s.push_str("\\n"),
                '\r' => s.push_str("\\r"),
                _ => s.push(c),
            }
        }
        s.push('"');
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_bare_when_safe() {
        assert_eq!(dotenv_value("postgres://u@h/db"), "postgres://u@h/db");
        assert_eq!(dotenv_value("abc123_-."), "abc123_-.");
    }

    #[test]
    fn dotenv_quotes_when_needed() {
        assert_eq!(dotenv_value("a b"), "\"a b\"");
        assert_eq!(dotenv_value("line1\nline2"), "\"line1\\nline2\"");
        assert_eq!(dotenv_value("say \"hi\""), "\"say \\\"hi\\\"\"");
        assert_eq!(dotenv_value(""), "\"\"");
    }

    #[test]
    fn build_command_injects_env_without_touching_parent() {
        std::env::remove_var("SECRETS_TEST_INJECT");
        let mut secrets = SecretMap::new();
        secrets.insert(
            "SECRETS_TEST_INJECT".to_string(),
            SecretString::from("value-123".to_string()),
        );

        // Portable child that echoes the injected variable.
        #[cfg(windows)]
        let program = vec![
            "cmd".to_string(),
            "/C".to_string(),
            "echo %SECRETS_TEST_INJECT%".to_string(),
        ];
        #[cfg(not(windows))]
        let program = vec![
            "sh".to_string(),
            "-c".to_string(),
            "printf %s \"$SECRETS_TEST_INJECT\"".to_string(),
        ];

        let output = build_command(&program, &secrets)
            .output()
            .expect("child should run");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("value-123"),
            "child did not receive injected env: {stdout:?}"
        );

        // Parent env must remain clean.
        assert!(std::env::var("SECRETS_TEST_INJECT").is_err());
    }
}
