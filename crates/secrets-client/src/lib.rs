//! Secrets Manager client library.
//!
//! The library surface is intentionally small: construct a [`Config`], create
//! an [`Api`], and fetch or set project secrets in-process.

#![forbid(unsafe_code)]

pub mod api;
pub mod config;
pub mod error;

mod cache;

#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "cli")]
pub mod commands;

pub use api::{Api, SecretMap};
pub use config::Config;
pub use error::{Error, Result};
