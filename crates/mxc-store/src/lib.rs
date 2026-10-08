//! `mxc-store` — SQLite persistence for the monocles chat desktop client.
//!
//! Holds accounts, roster/presence, conversations, messages and the PQ OMEMO2 key
//! stores. Passwords and the OMEMO identity private key never touch SQLite; they are
//! sealed in the platform secret service (libsecret) via [`secrets`].
//!
//! The pool is opened with `runtime-tokio` so it lives on the same tokio runtime that
//! drives `mxc-proto`. The GTK side never touches the DB directly — it goes through the
//! `mxc-proto` client actor, which owns this [`Store`].

use std::path::Path;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;

/// Secret-service key (not account-specific) for the local SQLCipher database.
const DB_KEY_ACCOUNT: &str = "@local";

pub mod accounts;
pub mod calls;
pub mod feeds;
pub mod roster;
pub mod messages;
pub mod omemo;
pub mod secrets;
pub mod settings;
pub mod stories;
pub mod webxdc;

pub use accounts::Account;
pub use calls::CallLogEntry;
pub use feeds::FeedPostRow;
pub use messages::{
    Conversation, Direction, MamCursor, MessageRow, MessageSearchRow, NewMessage, PendingMessage,
};
pub use roster::RosterItem;
pub use stories::StoryRow;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("secret service: {0}")]
    Secret(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Handle to the application database. Cheap to clone (wraps an `Arc`'d pool).
#[derive(Clone, Debug)]
pub struct Store {
    pool: SqlitePool,
    /// Serializes message dedup-then-insert so a live + MAM-catch-up delivery of the same
    /// message can't both pass the dedup check (the core runtime interleaves at awaits).
    insert_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
}

impl Store {
    /// Open (creating if needed) the encrypted database at `path` and run migrations.
    ///
    /// The DB is SQLCipher-encrypted with a random 32-byte key kept in the secret service.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let (key_hex, _created) = db_key().await?;
        Self::open_with_key(path.as_ref(), &key_hex).await
    }

    /// Open the database at `path` using the given hex SQLCipher key (no secret service).
    async fn open_with_key(path: &Path, key_hex: &str) -> Result<Self> {
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            // SQLCipher raw key (sqlx runs the `key` pragma before any other access).
            .pragma("key", format!("\"x'{key_hex}'\""))
            // WAL + synchronous=NORMAL is the recommended durable-but-fast combo: it skips
            // an fsync on every commit (safe under WAL), which is what made bursts of
            // presence/message writes occasionally take seconds under write-lock contention.
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .pragma("temp_store", "memory")
            .busy_timeout(std::time::Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(opts)
            .await?;

        sqlx::migrate!("./migrations").run(&pool).await?;

        // Restrict the file to the owner (defence-in-depth on top of the encryption).
        restrict_permissions(path);

        Ok(Self { pool, insert_lock: Default::default() })
    }

    /// Open an in-memory database (tests).
    pub async fn open_in_memory() -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool, insert_lock: Default::default() })
    }

    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

/// Fetch the SQLCipher key (hex) from the secret service, creating a fresh random 32-byte
/// key on first use. Returns `(hex_key, was_just_created)`.
async fn db_key() -> Result<(String, bool)> {
    match secrets::retrieve(secrets::kinds::DB_KEY, DB_KEY_ACCOUNT).await? {
        Some(bytes) => {
            let hex = String::from_utf8(bytes).map_err(|e| StoreError::Secret(e.to_string()))?;
            Ok((hex, false))
        }
        None => {
            use rand::RngCore;
            let mut key = [0u8; 32];
            rand::rng().fill_bytes(&mut key);
            let hex = hex::encode(key);
            secrets::store(secrets::kinds::DB_KEY, DB_KEY_ACCOUNT, hex.as_bytes()).await?;
            Ok((hex, true))
        }
    }
}

/// Restrict the SQLite file (and its WAL/SHM sidecars) to owner read/write only (0600).
#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let main = path.to_string_lossy().into_owned();
    for p in [main.clone(), format!("{main}-wal"), format!("{main}-shm")] {
        if let Ok(meta) = std::fs::metadata(&p) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(&p, perms);
        }
    }
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn migrations_apply_cleanly() {
        let store = Store::open_in_memory().await.expect("open");
        // smoke: insert + read back an account
        let id = store
            .upsert_account("arne@monocles.eu")
            .await
            .expect("insert account");
        let acc = store.account_by_jid("arne@monocles.eu").await.unwrap().unwrap();
        assert_eq!(acc.id, id);
        assert_eq!(acc.jid, "arne@monocles.eu");
    }

    #[tokio::test]
    async fn sqlcipher_encrypts_and_rejects_wrong_key() {
        let dir = std::env::temp_dir().join(format!("mxc-cipher-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("enc.db");
        let _ = std::fs::remove_file(&path);
        let key = "a".repeat(64); // 32-byte hex key

        // Create + write through SQLCipher.
        {
            let store = Store::open_with_key(&path, &key).await.expect("open keyed");
            store.upsert_account("arne@monocles.eu").await.unwrap();
        }

        // The raw file must NOT contain plaintext (it's encrypted).
        let raw = std::fs::read(&path).unwrap();
        assert!(
            !raw.windows(7).any(|w| w == b"monocle"),
            "plaintext leaked into the encrypted DB file"
        );
        // SQLite plaintext files start with "SQLite format 3\0"; encrypted ones don't.
        assert!(!raw.starts_with(b"SQLite format 3"), "DB header is not encrypted");

        // Reopen with the right key → data is there.
        {
            let store = Store::open_with_key(&path, &key).await.expect("reopen keyed");
            assert!(store.account_by_jid("arne@monocles.eu").await.unwrap().is_some());
        }

        // Wrong key → must fail.
        let wrong = "b".repeat(64);
        assert!(Store::open_with_key(&path, &wrong).await.is_err(), "wrong key opened the DB");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
