//! Secrets Manager client library.
//!
//! Exposed as a library (alongside the `secrets` binary) so the command
//! logic can be unit/integration tested.

#![forbid(unsafe_code)]

pub mod api;
pub mod cache;
pub mod cli;
pub mod commands;
pub mod config;
