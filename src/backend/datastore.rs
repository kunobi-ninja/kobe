//! PostgreSQL datastore management for k3s and k0s backends.
//!
//! Each cluster gets its own database in a shared PostgreSQL instance.
//! This module handles creating, dropping, and templating databases, as well as
//! rewriting connection URLs to point at per-cluster databases.
//!
//! All public functions accept a `prefix` parameter (e.g. `"k3s_"` or `"k0s_"`)
//! so the same module can be shared across distro-specific backends.
//!
//! **SQL injection safety**: database names cannot be parameterized in DDL
//! statements. We enforce a strict allowlist (`[a-zA-Z0-9_]`) and wrap names
//! in double quotes.

use anyhow::{Context, Result, bail};
use kunobi_reload::{BoxError, Reloadable, watch};
use sqlx::PgPool;
use tracing::{debug, info, warn};

/// Maximum length for a PostgreSQL identifier (63 bytes).
const MAX_IDENT_LEN: usize = 63;

/// One live PostgreSQL connection: the pool plus the base URL it was built from
/// (the URL carries the current credential, and per-cluster endpoints are
/// derived from it).
#[derive(Clone)]
pub struct DatastoreConn {
    pub pool: PgPool,
    pub base_url: String,
}

impl DatastoreConn {
    async fn connect(base_url: String) -> std::result::Result<Self, BoxError> {
        let pool = PgPool::connect(&base_url).await?;
        Ok(Self { pool, base_url })
    }
}

/// The operator's optional shared PostgreSQL datastore (k3s/k0s golden
/// templates). Three modes:
///
/// - `None` — no datastore configured; backends use the embedded SQLite store.
/// - `Static` — URL from the frozen `POSTGRES_URL` env var (legacy). A Postgres
///   password rotation requires an operator pod restart to pick up.
/// - `Reloading` — URL re-read from a mounted Secret directory (`POSTGRES_URL_DIR`,
///   a `url` file) via `kunobi-reload`. When the Secret rotates, the pool is
///   rebuilt in place within milliseconds, no restart (#91).
#[derive(Clone, Default)]
pub enum SharedDatastore {
    #[default]
    None,
    Static(DatastoreConn),
    Reloading(Reloadable<DatastoreConn>),
}

impl SharedDatastore {
    /// The current `(pool, base_url)`, cloned, if a datastore is configured and
    /// connected. Cheap (a `PgPool` clone is an `Arc` clone); re-read on every
    /// use so a rotation is observed without restarting.
    pub fn current(&self) -> Option<(PgPool, String)> {
        match self {
            SharedDatastore::None => None,
            SharedDatastore::Static(c) => Some((c.pool.clone(), c.base_url.clone())),
            SharedDatastore::Reloading(r) => {
                let c = r.borrow();
                Some((c.pool.clone(), c.base_url.clone()))
            }
        }
    }

    /// Build from the environment:
    /// - `POSTGRES_URL_DIR` set → watch that mounted-Secret dir's `url` file and
    ///   hot-reload the pool on rotation;
    /// - else `POSTGRES_URL` set → a static (non-reloading) connection;
    /// - else → no datastore.
    ///
    /// A connection/watch failure logs and degrades to `None` (embedded store),
    /// matching the previous best-effort behavior.
    pub async fn from_env() -> Self {
        if let Ok(dir) = std::env::var("POSTGRES_URL_DIR") {
            match watch(&dir)
                .spawn(|mount| async move {
                    let url = mount.read_str("url")?.trim().to_string();
                    DatastoreConn::connect(url).await
                })
                .await
            {
                Ok(reloadable) => {
                    info!(
                        dir = %dir,
                        "PostgreSQL connected via mounted Secret — credential hot-reload enabled"
                    );
                    SharedDatastore::Reloading(reloadable)
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        dir = %dir,
                        "Failed to start PostgreSQL credential watch; using embedded datastore"
                    );
                    SharedDatastore::None
                }
            }
        } else if let Ok(url) = std::env::var("POSTGRES_URL") {
            match DatastoreConn::connect(url).await {
                Ok(conn) => {
                    info!(
                        "PostgreSQL connected — golden templates enabled (static; set \
                         POSTGRES_URL_DIR to a mounted Secret to enable credential hot-reload)"
                    );
                    SharedDatastore::Static(conn)
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "Failed to connect to PostgreSQL, backends will use embedded datastore"
                    );
                    SharedDatastore::None
                }
            }
        } else {
            SharedDatastore::None
        }
    }
}

/// Sanitize a cluster name into a safe PostgreSQL database name.
///
/// - Replaces hyphens with underscores
/// - Prepends the given `prefix` (e.g. `"k3s_"` or `"k0s_"`)
/// - Strips any character not in `[a-zA-Z0-9_]`
/// - Truncates to 63 characters
pub fn sanitize_db_name(cluster_name: &str, prefix: &str) -> Result<String> {
    let cleaned: String = cluster_name
        .replace('-', "_")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();

    if cleaned.is_empty() {
        bail!(
            "Cluster name '{cluster_name}' produces an empty database identifier after sanitization"
        );
    }

    let mut db_name = format!("{prefix}{cleaned}");
    db_name.truncate(MAX_IDENT_LEN);
    Ok(db_name)
}

/// Create a new database for a cluster.
pub async fn create_database(pool: &PgPool, cluster_name: &str, prefix: &str) -> Result<()> {
    let db_name = sanitize_db_name(cluster_name, prefix)?;
    info!(db = %db_name, cluster = cluster_name, "Creating database");

    let sql = format!("CREATE DATABASE \"{db_name}\"");
    sqlx::query(&sql)
        .execute(pool)
        .await
        .with_context(|| format!("Failed to create database {db_name}"))?;

    debug!(db = %db_name, "Database created");
    Ok(())
}

/// Create a new database from a template (golden image).
#[allow(dead_code)]
pub async fn create_database_from_template(
    pool: &PgPool,
    cluster_name: &str,
    template_name: &str,
    prefix: &str,
) -> Result<()> {
    let db_name = sanitize_db_name(cluster_name, prefix)?;
    let template = sanitize_db_name(template_name, prefix)?;
    info!(
        db = %db_name,
        template = %template,
        "Creating database from template"
    );

    let sql = format!("CREATE DATABASE \"{db_name}\" TEMPLATE \"{template}\"");
    sqlx::query(&sql)
        .execute(pool)
        .await
        .with_context(|| format!("Failed to create database {db_name} from template {template}"))?;

    debug!(db = %db_name, "Database created from template");
    Ok(())
}

/// Mark a database as a template so it can be used with `CREATE DATABASE ... TEMPLATE`.
#[allow(dead_code)]
pub async fn mark_as_template(pool: &PgPool, cluster_name: &str, prefix: &str) -> Result<()> {
    let db_name = sanitize_db_name(cluster_name, prefix)?;
    info!(db = %db_name, "Marking database as template");

    let sql = format!("ALTER DATABASE \"{db_name}\" WITH is_template = true");
    sqlx::query(&sql)
        .execute(pool)
        .await
        .with_context(|| format!("Failed to mark {db_name} as template"))?;

    Ok(())
}

/// Remove the template flag from a database (required before it can be dropped).
#[allow(dead_code)]
pub async fn unmark_template(pool: &PgPool, cluster_name: &str, prefix: &str) -> Result<()> {
    let db_name = sanitize_db_name(cluster_name, prefix)?;
    info!(db = %db_name, "Unmarking database template flag");

    let sql = format!("ALTER DATABASE \"{db_name}\" WITH is_template = false");
    sqlx::query(&sql)
        .execute(pool)
        .await
        .with_context(|| format!("Failed to unmark {db_name} as template"))?;

    Ok(())
}

/// Drop a cluster's database, disconnecting any active sessions first.
pub async fn drop_database(pool: &PgPool, cluster_name: &str, prefix: &str) -> Result<()> {
    let db_name = sanitize_db_name(cluster_name, prefix)?;
    info!(db = %db_name, "Dropping database");

    // Terminate active connections to the database
    let disconnect_sql = format!(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{db_name}' AND pid <> pg_backend_pid()"
    );
    if let Err(e) = sqlx::query(&disconnect_sql).execute(pool).await {
        warn!(db = %db_name, error = %e, "Failed to disconnect sessions (may not exist)");
    }

    let sql = format!("DROP DATABASE IF EXISTS \"{db_name}\"");
    sqlx::query(&sql)
        .execute(pool)
        .await
        .with_context(|| format!("Failed to drop database {db_name}"))?;

    debug!(db = %db_name, "Database dropped");
    Ok(())
}

/// Rewrite a base PostgreSQL connection URL to point at a per-cluster database.
///
/// Given `postgres://user:pass@host:5432/admin_db` and cluster name `my-cluster`,
/// returns `postgres://user:pass@host:5432/k3s_my_cluster`.
pub fn cluster_endpoint(base_url: &str, cluster_name: &str, prefix: &str) -> Result<String> {
    let db_name = sanitize_db_name(cluster_name, prefix)?;
    let mut parsed = url::Url::parse(base_url)
        .with_context(|| format!("Invalid base PostgreSQL URL: {base_url}"))?;
    parsed.set_path(&format!("/{db_name}"));
    Ok(parsed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_datastore_none_is_default_and_returns_no_connection() {
        let ds = SharedDatastore::default();
        assert!(matches!(ds, SharedDatastore::None));
        assert!(ds.current().is_none());
    }

    // -- sanitize_db_name tests --

    #[test]
    fn test_sanitize_basic() {
        assert_eq!(
            sanitize_db_name("my-cluster", "k3s_").unwrap(),
            "k3s_my_cluster"
        );
    }

    #[test]
    fn test_sanitize_strips_special_chars() {
        assert_eq!(
            sanitize_db_name("pool.test/0", "k3s_").unwrap(),
            "k3s_pooltest0"
        );
    }

    #[test]
    fn test_sanitize_preserves_alphanumeric() {
        assert_eq!(
            sanitize_db_name("e2e_basic_01", "k3s_").unwrap(),
            "k3s_e2e_basic_01"
        );
    }

    #[test]
    fn test_sanitize_empty_after_cleaning() {
        assert!(sanitize_db_name("...", "k3s_").is_err());
    }

    #[test]
    fn test_sanitize_truncates_long_names() {
        let long_name = "a".repeat(100);
        let result = sanitize_db_name(&long_name, "k3s_").unwrap();
        assert!(result.len() <= MAX_IDENT_LEN);
        assert!(result.starts_with("k3s_"));
    }

    #[test]
    fn test_sanitize_hyphens_to_underscores() {
        assert_eq!(
            sanitize_db_name("pool-e2e-basic-0", "k3s_").unwrap(),
            "k3s_pool_e2e_basic_0"
        );
    }

    #[test]
    fn test_sanitize_with_k0s_prefix() {
        assert_eq!(
            sanitize_db_name("my-cluster", "k0s_").unwrap(),
            "k0s_my_cluster"
        );
    }

    // -- cluster_endpoint tests --

    #[test]
    fn test_cluster_endpoint_basic() {
        let result = cluster_endpoint(
            "postgres://user:pass@pghost:5432/admin",
            "my-cluster",
            "k3s_",
        )
        .unwrap();
        assert_eq!(result, "postgres://user:pass@pghost:5432/k3s_my_cluster");
    }

    #[test]
    fn test_cluster_endpoint_no_path() {
        let result =
            cluster_endpoint("postgres://user:pass@pghost:5432", "test-01", "k3s_").unwrap();
        assert_eq!(result, "postgres://user:pass@pghost:5432/k3s_test_01");
    }

    #[test]
    fn test_cluster_endpoint_invalid_url() {
        assert!(cluster_endpoint("not-a-url", "test", "k3s_").is_err());
    }

    #[test]
    fn test_cluster_endpoint_k0s_prefix() {
        let result = cluster_endpoint("postgres://u:p@h:5432/admin", "cl-1", "k0s_").unwrap();
        assert_eq!(result, "postgres://u:p@h:5432/k0s_cl_1");
    }
}
