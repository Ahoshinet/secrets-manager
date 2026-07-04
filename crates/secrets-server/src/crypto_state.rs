//! Master-key initialization and verification.
//!
//! On first run we generate a random salt, derive the key, and store an
//! encrypted sentinel ("verifier"). On subsequent runs we re-derive and
//! decrypt the sentinel to confirm the passphrase before serving — a
//! wrong passphrase fails loudly instead of silently corrupting data.

use anyhow::{anyhow, bail, Context, Result};
use rusqlite::Connection;
use secrecy::SecretString;
use secrets_crypto::{aad_bytes, decrypt, derive_key, encrypt, generate_salt, KdfParams, MasterKey};

use crate::repo;

const SENTINEL: &[u8] = b"secrets-manager-verifier-v1";

// meta keys
const K_SALT: &str = "kdf_salt";
const K_M: &str = "kdf_m_cost_kib";
const K_T: &str = "kdf_t_cost";
const K_P: &str = "kdf_p_cost";
const K_VNONCE: &str = "verifier_nonce";
const K_VCT: &str = "verifier_ct";

/// AAD binding the verifier record. Uses reserved names that can never
/// collide with a real project/key.
fn verifier_aad() -> Vec<u8> {
    aad_bytes("\u{0}meta", "\u{0}verifier")
}

fn u32_to_le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

fn le_to_u32(bytes: &[u8]) -> Result<u32> {
    let arr: [u8; 4] = bytes
        .try_into()
        .map_err(|_| anyhow!("corrupted kdf parameter in database"))?;
    Ok(u32::from_le_bytes(arr))
}

/// Initialize (first run) or verify (subsequent runs) the master key.
pub fn init_or_verify(conn: &Connection, passphrase: &SecretString) -> Result<MasterKey> {
    match repo::get_meta(conn, K_SALT).context("reading kdf salt")? {
        Some(salt) => verify(conn, passphrase, &salt),
        None => initialize(conn, passphrase),
    }
}

fn initialize(conn: &Connection, passphrase: &SecretString) -> Result<MasterKey> {
    let salt = generate_salt();
    let params = KdfParams::STRONG;
    let key = derive_key(passphrase, &salt, params).map_err(|e| anyhow!(e))?;

    let (nonce, ct) =
        encrypt(&key, SENTINEL, &verifier_aad()).map_err(|e| anyhow!(e))?;

    // Persist all crypto metadata atomically.
    let tx = conn.unchecked_transaction()?;
    repo::set_meta(&tx, K_SALT, &salt)?;
    repo::set_meta(&tx, K_M, &u32_to_le(params.m_cost_kib))?;
    repo::set_meta(&tx, K_T, &u32_to_le(params.t_cost))?;
    repo::set_meta(&tx, K_P, &u32_to_le(params.p_cost))?;
    repo::set_meta(&tx, K_VNONCE, &nonce)?;
    repo::set_meta(&tx, K_VCT, &ct)?;
    tx.commit()?;

    eprintln!("[info] initialized new master key (Argon2id m=256MiB, t=4, p=1)");
    Ok(key)
}

fn verify(conn: &Connection, passphrase: &SecretString, salt: &[u8]) -> Result<MasterKey> {
    let m = le_to_u32(&get_required(conn, K_M)?)?;
    let t = le_to_u32(&get_required(conn, K_T)?)?;
    let p = le_to_u32(&get_required(conn, K_P)?)?;
    let params = KdfParams {
        m_cost_kib: m,
        t_cost: t,
        p_cost: p,
    };

    let key = derive_key(passphrase, salt, params).map_err(|e| anyhow!(e))?;

    let nonce = get_required(conn, K_VNONCE)?;
    let ct = get_required(conn, K_VCT)?;

    decrypt(&key, &nonce, &ct, &verifier_aad()).map_err(|_| {
        anyhow!("passphrase verification failed (wrong passphrase or corrupted database)")
    })?;

    Ok(key)
}

fn get_required(conn: &Connection, key: &str) -> Result<Vec<u8>> {
    match repo::get_meta(conn, key)? {
        Some(v) => Ok(v),
        None => bail!("database is missing required crypto metadata ({key})"),
    }
}
