//! Master-key initialization and verification.
//!
//! On first run we generate a random salt, derive the key, and store an
//! encrypted sentinel ("verifier"). On subsequent runs we re-derive and
//! decrypt the sentinel to confirm the passphrase before serving — a
//! wrong passphrase fails loudly instead of silently corrupting data.

use anyhow::{anyhow, bail, Context, Result};
use rusqlite::{params, Connection};
use secrecy::{ExposeSecret, SecretString};
use secrets_crypto::{
    aad_bytes, decrypt, derive_key, encrypt, generate_salt, KdfParams, MasterKey,
};
use zeroize::Zeroize;

use crate::repo;

const SENTINEL: &[u8] = b"secrets-manager-verifier-v1";

// meta keys
const K_SALT: &str = "kdf_salt";
const K_M: &str = "kdf_m_cost_kib";
const K_T: &str = "kdf_t_cost";
const K_P: &str = "kdf_p_cost";
const K_VNONCE: &str = "verifier_nonce";
const K_VCT: &str = "verifier_ct";

// Local bounds on KDF parameters read from the database. The KDF metadata
// is not authenticated (it must be readable before any key exists), so a
// database writer could otherwise plant absurd Argon2 costs and DoS
// startup/rekey before the verifier decryption ever runs.
const KDF_M_COST_KIB_MIN: u32 = 8; // argon2 crate minimum
const KDF_M_COST_KIB_MAX: u32 = 1024 * 1024; // 1 GiB
const KDF_T_COST_MIN: u32 = 1;
const KDF_T_COST_MAX: u32 = 32;
const KDF_P_COST_MIN: u32 = 1;
const KDF_P_COST_MAX: u32 = 8;

fn validate_kdf_params(params: &KdfParams) -> Result<()> {
    let ok = (KDF_M_COST_KIB_MIN..=KDF_M_COST_KIB_MAX).contains(&params.m_cost_kib)
        && (KDF_T_COST_MIN..=KDF_T_COST_MAX).contains(&params.t_cost)
        && (KDF_P_COST_MIN..=KDF_P_COST_MAX).contains(&params.p_cost);
    if !ok {
        bail!(
            "kdf parameters stored in the database are outside the supported range \
             (m={} KiB, t={}, p={}); refusing to derive a key (possible tampering)",
            params.m_cost_kib,
            params.t_cost,
            params.p_cost
        );
    }
    Ok(())
}

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

/// Verify the current passphrase and re-encrypt every secret under a new
/// passphrase-derived key. The verifier and all KDF metadata are updated in
/// the same transaction as the secret ciphertexts.
pub fn rekey(
    conn: &Connection,
    current_passphrase: &SecretString,
    new_passphrase: &SecretString,
) -> Result<usize> {
    rekey_with_params(conn, current_passphrase, new_passphrase, KdfParams::STRONG)
}

fn rekey_with_params(
    conn: &Connection,
    current_passphrase: &SecretString,
    new_passphrase: &SecretString,
    new_params: KdfParams,
) -> Result<usize> {
    if current_passphrase.expose_secret() == new_passphrase.expose_secret() {
        bail!("new passphrase must differ from the current passphrase");
    }

    let old_key = match repo::get_meta(conn, K_SALT).context("reading kdf salt")? {
        Some(salt) => verify(conn, current_passphrase, &salt)?,
        None => bail!("cannot rekey an uninitialized database"),
    };

    let new_salt = generate_salt();
    let new_key = derive_key(new_passphrase, &new_salt, new_params).map_err(|e| anyhow!(e))?;

    struct Row {
        id: i64,
        project: String,
        key: String,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    }

    let tx = conn.unchecked_transaction()?;
    let rows = {
        let mut stmt = tx.prepare(
            "SELECT secrets.id, projects.name, secrets.key, secrets.nonce, secrets.ciphertext
             FROM secrets
             JOIN projects ON projects.id = secrets.project_id
             ORDER BY secrets.id",
        )?;
        let iter = stmt.query_map([], |r| {
            Ok(Row {
                id: r.get(0)?,
                project: r.get(1)?,
                key: r.get(2)?,
                nonce: r.get(3)?,
                ciphertext: r.get(4)?,
            })
        })?;
        iter.collect::<rusqlite::Result<Vec<_>>>()?
    };

    let count = rows.len();
    for row in rows {
        let aad = aad_bytes(&row.project, &row.key);
        let mut plaintext = decrypt(&old_key, &row.nonce, &row.ciphertext, &aad)
            .map_err(|_| anyhow!("failed to decrypt existing secret during rekey"))?;
        let (new_nonce, new_ct) = encrypt(&new_key, &plaintext, &aad).map_err(|e| anyhow!(e))?;
        plaintext.zeroize();
        tx.execute(
            "UPDATE secrets SET nonce = ?1, ciphertext = ?2 WHERE id = ?3",
            params![new_nonce, new_ct, row.id],
        )?;
    }

    let (verifier_nonce, verifier_ct) =
        encrypt(&new_key, SENTINEL, &verifier_aad()).map_err(|e| anyhow!(e))?;
    repo::set_meta(&tx, K_SALT, &new_salt)?;
    repo::set_meta(&tx, K_M, &u32_to_le(new_params.m_cost_kib))?;
    repo::set_meta(&tx, K_T, &u32_to_le(new_params.t_cost))?;
    repo::set_meta(&tx, K_P, &u32_to_le(new_params.p_cost))?;
    repo::set_meta(&tx, K_VNONCE, &verifier_nonce)?;
    repo::set_meta(&tx, K_VCT, &verifier_ct)?;
    tx.commit()?;

    Ok(count)
}

fn initialize(conn: &Connection, passphrase: &SecretString) -> Result<MasterKey> {
    initialize_with_params(conn, passphrase, KdfParams::STRONG)
}

fn initialize_with_params(
    conn: &Connection,
    passphrase: &SecretString,
    params: KdfParams,
) -> Result<MasterKey> {
    let salt = generate_salt();
    let key = derive_key(passphrase, &salt, params).map_err(|e| anyhow!(e))?;

    let (nonce, ct) = encrypt(&key, SENTINEL, &verifier_aad()).map_err(|e| anyhow!(e))?;

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
    validate_kdf_params(&params)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn cheap_params() -> KdfParams {
        KdfParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn rekey_reencrypts_existing_secrets_and_updates_verifier() {
        let conn = Connection::open_in_memory().unwrap();
        db::migrate(&conn).unwrap();

        let old_pass = SecretString::from("old-passphrase".to_string());
        let new_pass = SecretString::from("new-passphrase".to_string());
        let old_key = initialize_with_params(&conn, &old_pass, cheap_params()).unwrap();

        repo::create_project(&conn, "cdn").unwrap();
        let pid = repo::project_id(&conn, "cdn").unwrap().unwrap();
        let aad = aad_bytes("cdn", "DATABASE_URL");
        let (nonce, ciphertext) = encrypt(&old_key, b"postgres://secret", &aad).unwrap();
        repo::upsert_secret(&conn, pid, "DATABASE_URL", &nonce, &ciphertext).unwrap();

        let changed = rekey_with_params(&conn, &old_pass, &new_pass, cheap_params()).unwrap();
        assert_eq!(changed, 1);

        let salt = repo::get_meta(&conn, K_SALT).unwrap().unwrap();
        assert!(verify(&conn, &old_pass, &salt).is_err());
        let new_key = verify(&conn, &new_pass, &salt).unwrap();

        let rows = repo::list_secret_rows(&conn, pid).unwrap();
        assert_eq!(rows.len(), 1);
        assert_ne!(rows[0].nonce, nonce);
        assert_ne!(rows[0].ciphertext, ciphertext);
        let plaintext = decrypt(&new_key, &rows[0].nonce, &rows[0].ciphertext, &aad).unwrap();
        assert_eq!(plaintext, b"postgres://secret");
    }

    #[test]
    fn oversized_kdf_params_are_rejected_before_derivation() {
        let conn = Connection::open_in_memory().unwrap();
        db::migrate(&conn).unwrap();

        let pass = SecretString::from("passphrase".to_string());
        initialize_with_params(&conn, &pass, cheap_params()).unwrap();

        // Simulate a database writer planting a huge m_cost to DoS startup.
        repo::set_meta(&conn, K_M, &u32_to_le(u32::MAX)).unwrap();

        let salt = repo::get_meta(&conn, K_SALT).unwrap().unwrap();
        let err = verify(&conn, &pass, &salt).unwrap_err();
        assert!(
            err.to_string().contains("outside the supported range"),
            "unexpected error: {err}"
        );
    }
}
