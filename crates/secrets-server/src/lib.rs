//! Secrets Manager server library.
//!
//! Exposed as a library (in addition to the `secrets-server` binary) so the
//! HTTP router and data layer can be driven directly from integration tests.

#![forbid(unsafe_code)]

pub mod app;
pub mod audit;
pub mod auth;
pub mod commands;
pub mod config;
pub mod crypto_state;
pub mod db;
pub mod error;
pub mod handlers;
pub mod repo;
