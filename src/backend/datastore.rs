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

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use kunobi_reload::{BoxError, FromMount, Mount, ReloadStatus, Reloadable, watch};
use sqlx::{PgConnection, PgPool, Postgres, pool::PoolConnection};
use tracing::{debug, info, warn};

use sha2::{Digest, Sha256};

/// Maximum length for a PostgreSQL identifier (63 bytes).
const MAX_IDENT_LEN: usize = 63;

/// Versioned domain for the application-level PostgreSQL lifecycle fence.
///
/// PostgreSQL advisory locks are voluntary: they serialize kobe's own DDL but
/// cannot constrain an uncooperative superuser or provider control plane. The
/// lock and exact catalog reads are necessary but not sufficient for verified
/// destruction: the external-datastore placement gate remains closed until the
/// OID/attempt-bound rename and DROP state machine is implemented explicitly.
const LIFECYCLE_LOCK_DOMAIN: &[u8] = b"kobe-postgres-lifecycle-v1\0";

/// Exact immutable PostgreSQL identities captured in a creation manifest.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedPostgresIdentity<'a> {
    pub system_identifier: &'a str,
    pub database: &'a str,
    pub database_oid: &'a str,
    pub role: &'a str,
    pub role_oid: &'a str,
}

/// Independent post-destroy observation made while holding the lifecycle
/// advisory lock. `true` requires the recorded OID, original name, and the
/// deterministic attempt tombstone all to be absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedPostgresAbsence {
    pub database: bool,
    pub role: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostgresObjectKind {
    Database,
    Role,
}

impl PostgresObjectKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Database => "db",
            Self::Role => "role",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CatalogObject {
    oid: String,
    name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactCatalogState {
    Absent,
    Original,
    Tombstone,
    Mismatch,
}

/// Stable signed 64-bit key used by every kobe DDL path for one canonical
/// database name. A digest avoids PostgreSQL's process-randomized client hash
/// functions and keeps creation and teardown interoperable across restarts.
fn lifecycle_lock_key(database: &str) -> i64 {
    let mut hasher = Sha256::new();
    hasher.update(LIFECYCLE_LOCK_DOMAIN);
    hasher.update(database.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    i64::from_be_bytes(bytes)
}

/// Deterministic, identifier-safe tombstone bound to an immutable OID and the
/// durable teardown attempt. Retrying after a commit/lost-response uses the
/// same name and resumes from catalog state instead of guessing.
fn teardown_tombstone(
    kind: PostgresObjectKind,
    expected_oid: &str,
    attempt_id: &str,
) -> Result<String> {
    let oid = expected_oid
        .parse::<u32>()
        .with_context(|| format!("Invalid PostgreSQL {} OID", kind.label()))?;
    if oid == 0 {
        bail!("PostgreSQL {} OID must be non-zero", kind.label());
    }
    if attempt_id.trim().is_empty() {
        bail!("PostgreSQL teardown requires a durable attempt identifier");
    }

    let mut hasher = Sha256::new();
    hasher.update(b"kobe-postgres-tombstone-v1\0");
    hasher.update(kind.label().as_bytes());
    hasher.update([0]);
    hasher.update(oid.to_be_bytes());
    hasher.update([0]);
    hasher.update(attempt_id.as_bytes());
    let digest = hex::encode(hasher.finalize());
    let tombstone = format!("kobe_vd_{}_{oid:08x}_{}", kind.label(), &digest[..24]);
    debug_assert!(tombstone.len() <= MAX_IDENT_LEN);
    Ok(tombstone)
}

fn classify_exact_catalog(
    rows: &[CatalogObject],
    expected_oid: &str,
    original: &str,
    tombstone: &str,
) -> ExactCatalogState {
    let expected = rows.iter().filter(|row| row.oid == expected_oid).count();
    let original_count = rows.iter().filter(|row| row.name == original).count();
    let tombstone_count = rows.iter().filter(|row| row.name == tombstone).count();

    if expected > 1 || original_count > 1 || tombstone_count > 1 {
        return ExactCatalogState::Mismatch;
    }
    let expected_name = rows
        .iter()
        .find(|row| row.oid == expected_oid)
        .map(|row| row.name.as_str());
    match expected_name {
        Some(name) if name == original && tombstone_count == 0 => ExactCatalogState::Original,
        Some(name) if name == tombstone && original_count == 0 => ExactCatalogState::Tombstone,
        Some(_) => ExactCatalogState::Mismatch,
        None if original_count == 0 && tombstone_count == 0 => ExactCatalogState::Absent,
        None => ExactCatalogState::Mismatch,
    }
}

/// Acquire one physical connection and the session-scoped lifecycle fence.
///
/// The connection is marked `close_on_drop` *before* attempting the advisory
/// lock. Cancellation, panic, or an early error therefore closes the session
/// (and PostgreSQL releases its lock) instead of returning a locked connection
/// to sqlx's pool. Lifecycle DDL is rare enough that replacing this connection
/// is an intentional safety cost.
async fn acquire_lifecycle_connection(
    pool: &PgPool,
    database: &str,
) -> Result<(PoolConnection<Postgres>, i64)> {
    let key = lifecycle_lock_key(database);
    let mut connection = pool
        .acquire()
        .await
        .context("Failed to acquire PostgreSQL lifecycle connection")?;
    connection.close_on_drop();
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(key)
        .fetch_one(&mut *connection)
        .await
        .context("Failed to acquire PostgreSQL lifecycle advisory lock")?;
    if !acquired {
        bail!("PostgreSQL lifecycle advisory lock is busy for {database}");
    }
    Ok((connection, key))
}

async fn finish_lifecycle_connection<T>(
    mut connection: PoolConnection<Postgres>,
    key: i64,
    operation: Result<T>,
) -> Result<T> {
    let unlocked = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)")
        .bind(key)
        .fetch_one(&mut *connection)
        .await;
    let close = connection.close().await;

    match unlocked {
        Ok(true) => {}
        Ok(false) => bail!("PostgreSQL lifecycle advisory lock was not held at release"),
        Err(error) => {
            return Err(error).context("Failed to release PostgreSQL lifecycle advisory lock");
        }
    }
    close.context("Failed to close PostgreSQL lifecycle connection")?;
    operation
}

async fn ensure_system_identifier(connection: &mut PgConnection, expected: &str) -> Result<()> {
    if expected
        .parse::<u64>()
        .map_or(true, |identifier| identifier == 0)
    {
        bail!("Invalid expected PostgreSQL system identifier");
    }
    let observed: String =
        sqlx::query_scalar("SELECT system_identifier::text FROM pg_control_system()")
            .fetch_one(connection)
            .await
            .context("Failed to read PostgreSQL system identifier")?;
    if observed != expected {
        bail!("PostgreSQL cluster identity changed");
    }
    Ok(())
}

async fn database_catalog_state(
    connection: &mut PgConnection,
    expected_oid: &str,
    original: &str,
    tombstone: &str,
) -> Result<(ExactCatalogState, Option<(bool, bool)>)> {
    let rows: Vec<(String, String, bool, bool)> = sqlx::query_as(
        r#"
        SELECT oid::text,
               datname,
               datallowconn,
               datdba = (SELECT oid FROM pg_roles WHERE rolname = current_user)
        FROM pg_database
        WHERE oid::text = $1 OR datname = $2 OR datname = $3
        ORDER BY oid
        "#,
    )
    .bind(expected_oid)
    .bind(original)
    .bind(tombstone)
    .fetch_all(connection)
    .await
    .context("Failed to inspect exact PostgreSQL database identity")?;
    let objects: Vec<CatalogObject> = rows
        .iter()
        .map(|(oid, name, _, _)| CatalogObject {
            oid: oid.clone(),
            name: name.clone(),
        })
        .collect();
    let attributes = rows
        .iter()
        .find(|(oid, _, _, _)| oid == expected_oid)
        .map(|(_, _, allow_connections, owned_by_current)| (*allow_connections, *owned_by_current));
    Ok((
        classify_exact_catalog(&objects, expected_oid, original, tombstone),
        attributes,
    ))
}

async fn role_catalog_state(
    connection: &mut PgConnection,
    expected_oid: &str,
    original: &str,
    tombstone: &str,
) -> Result<(ExactCatalogState, Option<bool>)> {
    let rows: Vec<(String, String, bool)> = sqlx::query_as(
        r#"
        SELECT oid::text, rolname, rolcanlogin
        FROM pg_roles
        WHERE oid::text = $1 OR rolname = $2 OR rolname = $3
        ORDER BY oid
        "#,
    )
    .bind(expected_oid)
    .bind(original)
    .bind(tombstone)
    .fetch_all(connection)
    .await
    .context("Failed to inspect exact PostgreSQL role identity")?;
    let objects: Vec<CatalogObject> = rows
        .iter()
        .map(|(oid, name, _)| CatalogObject {
            oid: oid.clone(),
            name: name.clone(),
        })
        .collect();
    let can_login = rows
        .iter()
        .find(|(oid, _, _)| oid == expected_oid)
        .map(|(_, _, can_login)| *can_login);
    Ok((
        classify_exact_catalog(&objects, expected_oid, original, tombstone),
        can_login,
    ))
}

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

impl FromMount for DatastoreConn {
    async fn from_mount(mount: Mount) -> std::result::Result<Self, BoxError> {
        let url = mount.read_str("url")?.trim().to_string();
        Self::connect(url).await
    }

    /// Graceful teardown when a rotation swaps in a new pool: close the OLD pool
    /// so its connections send Postgres `Terminate` and in-flight queries drain,
    /// rather than being dropped abruptly (an async teardown `Drop` can't do).
    /// `PgPool::close()` waits for connections borrowed by in-flight `current()`
    /// clones to return first, so it composes safely.
    async fn retire(self: Arc<Self>) {
        self.pool.close().await;
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

    /// Reload health for the `Reloading` variant (`None` for the others). A
    /// `Stale` result means the mounted credential changed but the new value
    /// keeps failing to parse/connect — the operator is running on the previous
    /// credential. Surfaced by `/readyz` so a persistently-stale rotation is
    /// observable rather than silent.
    pub fn reload_status(&self) -> Option<ReloadStatus> {
        match self {
            SharedDatastore::Reloading(r) => Some(r.reload_status()),
            _ => None,
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
            // The FromMount/reloadable path (not .spawn) runs DatastoreConn::retire
            // on rotation, gracefully closing the superseded pool.
            match watch(&dir).reloadable::<DatastoreConn>().await {
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
    if db_name.len() > MAX_IDENT_LEN {
        // Plain truncation makes two distinct clusters share one identifier —
        // and since the role now shares that identifier, the second cluster's
        // `ensure_cluster_role` would reset the FIRST cluster's role password
        // and hand its owner credential to a different tenant. Keep a digest of
        // the full name so distinct inputs stay distinct.
        use sha2::{Digest, Sha256};
        let digest = hex::encode(Sha256::digest(db_name.as_bytes()));
        db_name.truncate(MAX_IDENT_LEN - 9);
        db_name.push('_');
        db_name.push_str(&digest[..8]);
    }
    Ok(db_name)
}

/// Non-secret identity of the PostgreSQL server selected by a connection URL.
///
/// Credentials, database path, query parameters, and fragments are deliberately
/// excluded. The resulting digest can be persisted in CR status and compared at
/// teardown without publishing a password or silently treating a different
/// server as the one that held the instance database.
pub fn endpoint_identity_digest(base_url: &str) -> Result<String> {
    let parsed = url::Url::parse(base_url).context("Invalid PostgreSQL datastore URL")?;
    let host = parsed
        .host_str()
        .filter(|host| !host.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("PostgreSQL datastore URL has no host"))?;
    let port = parsed.port_or_known_default().unwrap_or(5432);
    let identity = format!("{}://{host}:{port}", parsed.scheme().to_ascii_lowercase());
    Ok(hex::encode(Sha256::digest(identity.as_bytes())))
}

/// PostgreSQL cluster and per-instance object identities observed by one
/// backend session and one statement snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterObjectIdentity {
    pub system_identifier: String,
    pub database_oid: Option<String>,
    pub role_oid: Option<String>,
}

/// Capture the cluster, database and role identity without mixing observations
/// from different pooled connections. This matters when a hostname is backed
/// by more than one server: three independent pool queries could otherwise
/// assemble provenance that never existed on any one PostgreSQL cluster.
/// The system identifier is initialized with the cluster, so DNS repointing or
/// an in-place reinitialization cannot masquerade as the original datastore.
pub async fn cluster_object_identity(
    pool: &PgPool,
    cluster_name: &str,
    prefix: &str,
) -> Result<ClusterObjectIdentity> {
    let name = sanitize_db_name(cluster_name, prefix)?;
    let (system_identifier, database_oid, role_oid): (String, Option<String>, Option<String>) =
        sqlx::query_as(
            r#"
        SELECT control.system_identifier::text,
               (SELECT oid::text FROM pg_database WHERE datname = $1),
               (SELECT oid::text FROM pg_roles WHERE rolname = $1)
        FROM pg_control_system() AS control
        "#,
        )
        .bind(name)
        .fetch_one(pool)
        .await
        .context("Failed to capture PostgreSQL cluster object identity")?;
    if system_identifier
        .parse::<u64>()
        .map_or(true, |identifier| identifier == 0)
    {
        bail!("PostgreSQL returned an invalid system identifier");
    }
    Ok(ClusterObjectIdentity {
        system_identifier,
        database_oid,
        role_oid,
    })
}

/// True iff `code` is PostgreSQL's `duplicate_database` SQLSTATE (`42P04`),
/// i.e. the `CREATE DATABASE` failed only because the database already exists.
///
/// Extracted as a pure helper so it can be unit-tested without simulating a
/// live sqlx error.
fn is_duplicate_db_error(code: Option<&str>) -> bool {
    code == Some("42P04")
}

/// Create a new database for a cluster.
///
/// Idempotent: PostgreSQL has no `CREATE DATABASE IF NOT EXISTS`, so a
/// "database already exists" error (`42P04`) is treated as success. This
/// matters because `create()` re-runs on every `Creating && !provisioned`
/// reconcile re-entry: the first `create_database` that errors *after* the
/// `CREATE DATABASE` actually succeeded (e.g. a transient PG blip or a
/// `wait_ready` timeout downstream) leaves the database in place, and the
/// next reconcile would otherwise hit "already exists" → `Err` → `Failed`
/// forever → recycle storm.
async fn create_database_on_connection(
    connection: &mut PgConnection,
    cluster_name: &str,
    prefix: &str,
) -> Result<()> {
    let db_name = sanitize_db_name(cluster_name, prefix)?;
    info!(db = %db_name, cluster = cluster_name, "Creating database");

    let sql = format!("CREATE DATABASE \"{db_name}\"");
    match sqlx::query(&sql).execute(&mut *connection).await {
        Ok(_) => {
            debug!(db = %db_name, "Database created");
            revoke_public_connect(connection, &db_name).await
        }
        Err(e) => {
            if let Some(dberr) = e.as_database_error()
                && is_duplicate_db_error(dberr.code().as_deref())
            {
                debug!(db = %db_name, "Database already exists, treating create as idempotent no-op");
                return revoke_public_connect(connection, &db_name).await;
            }
            Err(e).with_context(|| format!("Failed to create database {db_name}"))
        }
    }
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
    let (mut connection, key) = acquire_lifecycle_connection(pool, &db_name).await?;
    let operation = async {
        let template = sanitize_db_name(template_name, prefix)?;
        info!(
            db = %db_name,
            template = %template,
            "Creating database from template"
        );

        let sql = format!("CREATE DATABASE \"{db_name}\" TEMPLATE \"{template}\"");
        sqlx::query(&sql)
            .execute(&mut *connection)
            .await
            .with_context(|| {
                format!("Failed to create database {db_name} from template {template}")
            })?;

        debug!(db = %db_name, "Database created from template");
        Ok(())
    }
    .await;
    finish_lifecycle_connection(connection, key, operation).await
}

/// Mark a database as a template so it can be used with `CREATE DATABASE ... TEMPLATE`.
#[allow(dead_code)]
pub async fn mark_as_template(pool: &PgPool, cluster_name: &str, prefix: &str) -> Result<()> {
    let db_name = sanitize_db_name(cluster_name, prefix)?;
    let (mut connection, key) = acquire_lifecycle_connection(pool, &db_name).await?;
    let operation = async {
        info!(db = %db_name, "Marking database as template");

        let sql = format!("ALTER DATABASE \"{db_name}\" WITH is_template = true");
        sqlx::query(&sql)
            .execute(&mut *connection)
            .await
            .with_context(|| format!("Failed to mark {db_name} as template"))?;

        Ok(())
    }
    .await;
    finish_lifecycle_connection(connection, key, operation).await
}

/// Remove the template flag from a database (required before it can be dropped).
#[allow(dead_code)]
pub async fn unmark_template(pool: &PgPool, cluster_name: &str, prefix: &str) -> Result<()> {
    let db_name = sanitize_db_name(cluster_name, prefix)?;
    let (mut connection, key) = acquire_lifecycle_connection(pool, &db_name).await?;
    let operation = async {
        info!(db = %db_name, "Unmarking database template flag");

        let sql = format!("ALTER DATABASE \"{db_name}\" WITH is_template = false");
        sqlx::query(&sql)
            .execute(&mut *connection)
            .await
            .with_context(|| format!("Failed to unmark {db_name} template flag"))?;

        Ok(())
    }
    .await;
    finish_lifecycle_connection(connection, key, operation).await
}

/// Take ownership of a cluster database back before dropping it.
///
/// `ensure_cluster_role` transfers ownership to the per-cluster role so kine can
/// create its tables. `DROP DATABASE` then requires the caller to own it or be a
/// superuser — and membership granted via `GRANT ... TO CURRENT_USER` is NOT
/// enough on PostgreSQL 16, where `createrole_self_grant` defaults to empty and
/// the membership carries no inherited privileges. Without reclaiming ownership
/// first, a non-superuser operator silently orphans a database and then a role
/// on every teardown.
///
/// Best-effort: on a superuser operator this is redundant, and if it fails the
/// drop below reports the real problem.
pub async fn reclaim_database_ownership(
    pool: &PgPool,
    cluster_name: &str,
    prefix: &str,
) -> Result<()> {
    let db_name = sanitize_db_name(cluster_name, prefix)?;
    let (mut connection, key) = acquire_lifecycle_connection(pool, &db_name).await?;
    let operation = async {
        sqlx::query(&format!(
            "ALTER DATABASE \"{db_name}\" OWNER TO CURRENT_USER"
        ))
        .execute(&mut *connection)
        .await
        .with_context(|| format!("Failed to reclaim ownership of database {db_name}"))?;
        debug!(db = %db_name, "Ownership reclaimed for drop");
        Ok(())
    }
    .await;
    finish_lifecycle_connection(connection, key, operation).await
}

/// Drop a cluster database during legacy, non-verified cleanup.
///
/// This remains name-addressed and must never be used as verified teardown
/// evidence. The lifecycle lock only serializes cooperating kobe DDL actors;
/// it cannot fence an external PostgreSQL superuser.
pub async fn drop_database(pool: &PgPool, cluster_name: &str, prefix: &str) -> Result<()> {
    let db_name = sanitize_db_name(cluster_name, prefix)?;
    let (mut connection, key) = acquire_lifecycle_connection(pool, &db_name).await?;
    let operation = async {
        info!(db = %db_name, "Dropping database");

        // Legacy cleanup has no immutable OID. It is still serialized with
        // provisioning and verified destroy so kobe never supplies the
        // uncooperative same-name actor excluded by the trust boundary.
        if let Err(e) = sqlx::query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname = $1 AND pid <> pg_backend_pid()",
        )
        .bind(&db_name)
        .execute(&mut *connection)
        .await
        {
            warn!(db = %db_name, error = %e, "Failed to disconnect sessions (may not exist)");
        }

        let sql = format!("DROP DATABASE IF EXISTS \"{db_name}\"");
        sqlx::query(&sql)
            .execute(&mut *connection)
            .await
            .with_context(|| format!("Failed to drop database {db_name}"))?;

        debug!(db = %db_name, "Database dropped");
        Ok(())
    }
    .await;
    finish_lifecycle_connection(connection, key, operation).await
}

/// Drop PostgreSQL's default `CONNECT` grant to `PUBLIC` on a database.
///
/// Runs immediately after `CREATE DATABASE`, in the same function, so no
/// Kubernetes round-trip sits between creating the database and locking it
/// down: during such a window every other tenant role can still connect.
///
/// NOTE: this does not revoke `CREATE` on the `public` SCHEMA, which would
/// require a second connection into the new database. PostgreSQL 15 removed
/// that default grant; on 14 and older, or a cluster upgraded from one, a
/// connected role could still create objects there. kobe targets 15+.
async fn revoke_public_connect(connection: &mut PgConnection, db_name: &str) -> Result<()> {
    sqlx::query(&format!(
        "REVOKE CONNECT ON DATABASE \"{db_name}\" FROM PUBLIC"
    ))
    .execute(connection)
    .await
    .with_context(|| format!("Failed to revoke PUBLIC connect on database {db_name}"))?;
    debug!(db = %db_name, "PUBLIC connect revoked");
    Ok(())
}

/// True iff `code` is PostgreSQL's `duplicate_object` SQLSTATE (`42710`),
/// i.e. `CREATE ROLE` failed only because the role already exists.
fn is_duplicate_role_error(code: Option<&str>) -> bool {
    code == Some("42710")
}

/// Rewrite a base PostgreSQL URL to point at a per-cluster database AS a
/// per-cluster role.
///
/// This is the isolation boundary. `cluster_endpoint` (below) only swapped the
/// database path and left `user:pass` identical for every cluster — so any
/// tenant who could read their own endpoint could reach every other tenant's
/// database by editing the path. The guest control plane must therefore be
/// handed a credential that is useless anywhere but its own database.
///
/// Assume the guest sees this string: the k3s server takes it as
/// `--datastore-endpoint=` on its command line, and the k3s server node is
/// schedulable and untainted by default, so a tenant with cluster-admin can
/// read it out of `/proc`. k0s writes it into its config ConfigMap. Neither is
/// a secret from the tenant, and neither can be.
pub fn cluster_endpoint_as_role(
    base_url: &str,
    cluster_name: &str,
    prefix: &str,
    password: &str,
) -> Result<String> {
    let db_name = sanitize_db_name(cluster_name, prefix)?;
    let mut parsed = url::Url::parse(base_url)
        .with_context(|| format!("Invalid base PostgreSQL URL: {base_url}"))?;
    parsed.set_path(&format!("/{db_name}"));
    // The role shares the database's identifier: PostgreSQL keeps roles and
    // databases in separate namespaces, so no suffix is needed — and a suffix
    // could push past the 63-character identifier limit that sanitize_db_name
    // already truncates to.
    parsed
        .set_username(&db_name)
        .map_err(|()| anyhow::anyhow!("Cannot set username on base URL: {base_url}"))?;
    parsed
        .set_password(Some(password))
        .map_err(|()| anyhow::anyhow!("Cannot set password on base URL: {base_url}"))?;
    Ok(parsed.to_string())
}

/// Create (or update the password of) the per-cluster login role, make it own
/// the cluster database, and revoke the default `PUBLIC` connect privilege.
///
/// Idempotent for the same reason `create_database` is: `create()` re-runs on
/// every `Creating && !provisioned` reconcile re-entry, so an existing role is
/// a no-op that refreshes the password rather than an error.
///
/// `REVOKE CONNECT ... FROM PUBLIC` matters because PostgreSQL grants CONNECT
/// to PUBLIC on every new database by default. Without it, one cluster's role
/// could still connect to another cluster's database.
async fn ensure_cluster_role_on_connection(
    connection: &mut PgConnection,
    cluster_name: &str,
    prefix: &str,
    password: &str,
) -> Result<String> {
    let name = sanitize_db_name(cluster_name, prefix)?;
    info!(role = %name, cluster = cluster_name, "Ensuring per-cluster datastore role");

    // Passwords are generated by the caller and never interpolated from user
    // input, but quote defensively anyway: a literal `'` would otherwise end
    // the string and change the statement.
    let quoted_password = password.replace('\'', "''");

    let create = format!("CREATE ROLE \"{name}\" LOGIN PASSWORD '{quoted_password}'");
    match sqlx::query(&create).execute(&mut *connection).await {
        Ok(_) => debug!(role = %name, "Role created"),
        Err(e) => {
            let duplicate = e
                .as_database_error()
                .is_some_and(|dberr| is_duplicate_role_error(dberr.code().as_deref()));
            if !duplicate {
                return Err(e).with_context(|| format!("Failed to create role {name}"));
            }
            debug!(role = %name, "Role exists; refreshing password");
            let alter = format!("ALTER ROLE \"{name}\" LOGIN PASSWORD '{quoted_password}'");
            sqlx::query(&alter)
                .execute(&mut *connection)
                .await
                .with_context(|| format!("Failed to refresh password for role {name}"))?;
        }
    }

    // `ALTER DATABASE ... OWNER TO` requires the caller to be a MEMBER of the
    // target role (or superuser). A plain CREATEDB/CREATEROLE operator account
    // is neither, so grant membership first or ownership transfer fails and
    // provisioning breaks outright.
    sqlx::query(&format!("GRANT \"{name}\" TO CURRENT_USER"))
        .execute(&mut *connection)
        .await
        .with_context(|| format!("Failed to grant membership of {name} to the operator role"))?;

    // Ownership lets kine create its own tables in the database.
    sqlx::query(&format!("ALTER DATABASE \"{name}\" OWNER TO \"{name}\""))
        .execute(&mut *connection)
        .await
        .with_context(|| format!("Failed to give {name} ownership of its database"))?;

    // PUBLIC connect is revoked in `create_database`, immediately after the
    // database exists, so there is no window here.
    Ok(name)
}

/// Provision the database and tenant role under one session advisory lock.
///
/// The password Secret is materialized by the caller first, before any tenant
/// workload exists, and is retained on failure for an idempotent retry. Keeping
/// both DDL phases on one physical session prevents verified teardown from
/// interleaving between database creation and its role/ownership hardening.
pub async fn provision_cluster_datastore(
    pool: &PgPool,
    cluster_name: &str,
    prefix: &str,
    password: &str,
) -> Result<String> {
    let name = sanitize_db_name(cluster_name, prefix)?;
    let (mut connection, key) = acquire_lifecycle_connection(pool, &name).await?;
    let operation = async {
        create_database_on_connection(&mut connection, cluster_name, prefix).await?;
        ensure_cluster_role_on_connection(&mut connection, cluster_name, prefix, password).await
    }
    .await;
    finish_lifecycle_connection(connection, key, operation).await
}

/// Drop the per-cluster role. Call AFTER `drop_database`: PostgreSQL refuses to
/// drop a role that still owns objects.
/// Whether this cluster's database still exists.
///
/// Verification, not cleanup: `DROP DATABASE IF EXISTS` succeeding proves the
/// statement ran, not that the database is gone — a concurrent recreate, a
/// failed drop that only warned, or a connection to a different server all
/// leave it present. Teardown evidence has to come from a separate read.
///
/// An error is deliberately propagated rather than reported as "absent". A
/// query that could not run is uncertainty, and uncertainty must quarantine.
pub async fn database_exists(pool: &PgPool, cluster_name: &str, prefix: &str) -> Result<bool> {
    let db_name = sanitize_db_name(cluster_name, prefix)?;
    let found: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM pg_database WHERE datname = $1")
        .bind(&db_name)
        .fetch_optional(pool)
        .await
        .with_context(|| format!("Failed to check whether database {db_name} exists"))?;
    Ok(found.is_some())
}

/// Whether this cluster's per-cluster role still exists.
///
/// Separate from the database on purpose: a role can outlive the database it
/// owned, and it carries credentials. Dropping the database while leaving the
/// role behind is exactly the leak that would otherwise sit inside a receipt
/// claiming the footprint is gone.
pub async fn cluster_role_exists(pool: &PgPool, cluster_name: &str, prefix: &str) -> Result<bool> {
    let role_name = sanitize_db_name(cluster_name, prefix)?;
    let found: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM pg_roles WHERE rolname = $1")
        .bind(&role_name)
        .fetch_optional(pool)
        .await
        .with_context(|| format!("Failed to check whether role {role_name} exists"))?;
    Ok(found.is_some())
}

pub async fn drop_cluster_role(pool: &PgPool, cluster_name: &str, prefix: &str) -> Result<()> {
    let name = sanitize_db_name(cluster_name, prefix)?;
    let (mut connection, key) = acquire_lifecycle_connection(pool, &name).await?;
    let operation = async {
        info!(role = %name, "Dropping per-cluster datastore role");
        sqlx::query(&format!("DROP ROLE IF EXISTS \"{name}\""))
            .execute(&mut *connection)
            .await
            .with_context(|| format!("Failed to drop role {name}"))?;
        Ok(())
    }
    .await;
    finish_lifecycle_connection(connection, key, operation).await
}

fn validate_manifest_identifier(identifier: &str, kind: &str) -> Result<()> {
    if identifier.is_empty()
        || identifier.len() > MAX_IDENT_LEN
        || !identifier
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        bail!("Manifest PostgreSQL {kind} name is not a safe identifier");
    }
    Ok(())
}

/// Re-observe exact absence for receipt generation under the same lifecycle
/// fence used by creation and destruction.
///
/// `true` requires the expected OID and both the original and deterministic
/// attempt-tombstone names to be absent. A same-name replacement or an expected
/// OID moved under a third name remains `false`; an unreadable/different
/// PostgreSQL cluster is an error and therefore can never become proof.
pub async fn verify_cluster_datastore_absence(
    pool: &PgPool,
    identity: VerifiedPostgresIdentity<'_>,
    attempt_id: &str,
) -> Result<VerifiedPostgresAbsence> {
    validate_manifest_identifier(identity.database, "database")?;
    validate_manifest_identifier(identity.role, "role")?;
    let database_tombstone = teardown_tombstone(
        PostgresObjectKind::Database,
        identity.database_oid,
        attempt_id,
    )?;
    let role_tombstone =
        teardown_tombstone(PostgresObjectKind::Role, identity.role_oid, attempt_id)?;
    let (mut connection, key) = acquire_lifecycle_connection(pool, identity.database).await?;
    let operation = async {
        ensure_system_identifier(&mut connection, identity.system_identifier).await?;
        let (database, _) = database_catalog_state(
            &mut connection,
            identity.database_oid,
            identity.database,
            &database_tombstone,
        )
        .await?;
        let (role, _) = role_catalog_state(
            &mut connection,
            identity.role_oid,
            identity.role,
            &role_tombstone,
        )
        .await?;
        Ok(VerifiedPostgresAbsence {
            database: database == ExactCatalogState::Absent,
            role: role == ExactCatalogState::Absent,
        })
    }
    .await;
    finish_lifecycle_connection(connection, key, operation).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog(oid: &str, name: &str) -> CatalogObject {
        CatalogObject {
            oid: oid.into(),
            name: name.into(),
        }
    }

    #[test]
    fn lifecycle_lock_key_is_stable_and_name_scoped() {
        assert_eq!(
            lifecycle_lock_key("k3s_pool_0"),
            lifecycle_lock_key("k3s_pool_0")
        );
        assert_ne!(
            lifecycle_lock_key("k3s_pool_0"),
            lifecycle_lock_key("k3s_pool_1")
        );
    }

    #[test]
    fn teardown_tombstone_is_attempt_oid_and_kind_bound() {
        let first = teardown_tombstone(PostgresObjectKind::Database, "16384", "attempt-1").unwrap();
        assert_eq!(
            first,
            teardown_tombstone(PostgresObjectKind::Database, "16384", "attempt-1").unwrap()
        );
        assert_ne!(
            first,
            teardown_tombstone(PostgresObjectKind::Database, "16384", "attempt-2").unwrap()
        );
        assert_ne!(
            first,
            teardown_tombstone(PostgresObjectKind::Database, "16385", "attempt-1").unwrap()
        );
        assert_ne!(
            first,
            teardown_tombstone(PostgresObjectKind::Role, "16384", "attempt-1").unwrap()
        );
        assert!(first.len() <= MAX_IDENT_LEN);
        assert!(
            first
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
        );
        assert!(teardown_tombstone(PostgresObjectKind::Database, "0", "attempt-1").is_err());
        assert!(teardown_tombstone(PostgresObjectKind::Database, "16384", "").is_err());
    }

    #[test]
    fn exact_catalog_classifier_accepts_only_original_tombstone_or_full_absence() {
        let original = "k3s_c1";
        let tombstone = "kobe_vd_db_00004000_deadbeef";
        let oid = "16384";

        assert_eq!(
            classify_exact_catalog(&[catalog(oid, original)], oid, original, tombstone),
            ExactCatalogState::Original
        );
        assert_eq!(
            classify_exact_catalog(&[catalog(oid, tombstone)], oid, original, tombstone),
            ExactCatalogState::Tombstone
        );
        assert_eq!(
            classify_exact_catalog(&[], oid, original, tombstone),
            ExactCatalogState::Absent
        );

        for rows in [
            vec![catalog("999", original)],
            vec![catalog("999", tombstone)],
            vec![catalog(oid, "third_name")],
            vec![catalog(oid, original), catalog("999", tombstone)],
            vec![catalog(oid, tombstone), catalog("999", original)],
        ] {
            assert_eq!(
                classify_exact_catalog(&rows, oid, original, tombstone),
                ExactCatalogState::Mismatch,
                "unsafe catalog state was accepted: {rows:?}"
            );
        }
    }

    #[test]
    fn endpoint_identity_excludes_credentials_and_database_path() {
        let first = endpoint_identity_digest(
            "postgresql://operator:old-secret@db.internal:5432/postgres?sslmode=require",
        )
        .unwrap();
        let rotated = endpoint_identity_digest(
            "postgresql://other:new-secret@db.internal:5432/template?application_name=kobe",
        )
        .unwrap();
        let other_host = endpoint_identity_digest(
            "postgresql://operator:old-secret@other.internal:5432/postgres",
        )
        .unwrap();
        assert_eq!(first, rotated);
        assert_ne!(first, other_host);
        assert!(!first.contains("secret"));
    }

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

    /// `create_database` is idempotent: only PostgreSQL's `duplicate_database`
    /// SQLSTATE (`42P04`) is swallowed. We can't easily fabricate a live sqlx
    /// `DatabaseError` in a unit test, so we lock the pure detector instead.
    #[test]
    fn test_is_duplicate_db_error() {
        assert!(is_duplicate_db_error(Some("42P04")));
        assert!(!is_duplicate_db_error(Some("42501"))); // insufficient_privilege
        assert!(!is_duplicate_db_error(Some("")));
        assert!(!is_duplicate_db_error(None));
    }

    // ── per-cluster role isolation ────────────────────────────────────

    /// The regression this exists to prevent.
    ///
    /// `cluster_endpoint` swapped only the database path, so every cluster was
    /// handed the same `user:pass`. A tenant who could read their own endpoint
    /// could edit the path and reach any other tenant's database. The guest CAN
    /// read it: k3s takes it as `--datastore-endpoint=` on a server node that is
    /// schedulable and untainted by default, and k0s writes it into a ConfigMap.
    #[test]
    fn role_endpoint_does_not_carry_the_admin_credential() {
        let base = "postgres://kobeadmin:supersecret@pg.internal:5432/postgres";
        let ep = cluster_endpoint_as_role(base, "my-cluster", "k3s_", "perclusterpw").unwrap();

        assert!(!ep.contains("kobeadmin"), "admin user leaked into {ep}");
        assert!(
            !ep.contains("supersecret"),
            "admin password leaked into {ep}"
        );
        assert!(ep.contains("k3s_my_cluster:perclusterpw@"), "{ep}");
        assert!(ep.ends_with("/k3s_my_cluster"), "{ep}");
    }

    /// Two clusters must not receive interchangeable credentials.
    #[test]
    fn two_clusters_get_distinct_roles() {
        let base = "postgres://admin:pw@pg:5432/postgres";
        let a = cluster_endpoint_as_role(base, "alpha", "k3s_", "pw-a").unwrap();
        let b = cluster_endpoint_as_role(base, "beta", "k3s_", "pw-b").unwrap();
        assert!(a.contains("k3s_alpha:pw-a@"), "{a}");
        assert!(b.contains("k3s_beta:pw-b@"), "{b}");
        assert_ne!(a, b);
    }

    /// The role reuses the database identifier, so it inherits the same 63-char
    /// truncation. A suffix would risk exceeding PostgreSQL's identifier limit
    /// and silently producing a role name that does not match the database.
    #[test]
    fn role_name_matches_the_database_name_exactly() {
        let long = "a".repeat(80);
        let db = sanitize_db_name(&long, "k3s_").unwrap();
        let ep =
            cluster_endpoint_as_role("postgres://a:b@h:5432/postgres", &long, "k3s_", "x").unwrap();
        assert!(db.len() <= MAX_IDENT_LEN);
        assert!(
            ep.contains(&format!("{db}:x@")),
            "role must equal db name: {ep}"
        );
        assert!(ep.ends_with(&format!("/{db}")), "{ep}");
    }

    /// A password containing URL-significant characters must survive intact.
    #[test]
    fn role_password_is_percent_encoded_in_the_url() {
        let ep = cluster_endpoint_as_role(
            "postgres://a:b@h:5432/postgres",
            "c",
            "k3s_",
            "p@ss:w/rd?x#y",
        )
        .unwrap();
        // Round-trip through the parser: whatever encoding is applied, the
        // password must decode back to the original or kine cannot connect.
        let parsed = url::Url::parse(&ep).unwrap();
        let decoded = percent_decode(parsed.password().expect("password present"));
        assert_eq!(decoded, "p@ss:w/rd?x#y", "password mangled in {ep}");
        assert_eq!(parsed.username(), "k3s_c");
    }

    fn percent_decode(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%'
                && i + 2 < bytes.len()
                && let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16)
            {
                out.push(b);
                i += 3;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn duplicate_role_sqlstate_is_recognised() {
        assert!(is_duplicate_role_error(Some("42710")));
        assert!(!is_duplicate_role_error(Some("42P04")));
        assert!(!is_duplicate_role_error(None));
    }

    /// Two cluster names that share a long prefix must not collapse onto one
    /// identifier: the role now shares that identifier too, so the second
    /// cluster's `ensure_cluster_role` would reset the FIRST cluster's role
    /// password and hand its owner credential to a different tenant.
    #[test]
    fn long_names_sharing_a_prefix_do_not_collide() {
        let a = format!("{}xxxx", "a".repeat(59));
        let b = format!("{}yyyy", "a".repeat(59));
        let da = sanitize_db_name(&a, "k3s_").unwrap();
        let db = sanitize_db_name(&b, "k3s_").unwrap();
        assert_ne!(da, db, "distinct clusters collapsed onto {da}");
        assert!(da.len() <= MAX_IDENT_LEN);
        assert!(db.len() <= MAX_IDENT_LEN);
    }

    /// Same input must always map to the same identifier, or a reconcile would
    /// provision a second database for an existing cluster.
    #[test]
    fn truncated_identifiers_are_deterministic() {
        let n = "b".repeat(80);
        assert_eq!(
            sanitize_db_name(&n, "k0s_").unwrap(),
            sanitize_db_name(&n, "k0s_").unwrap()
        );
    }

    /// Names short enough not to truncate must be untouched, so this change
    /// cannot rename the database of any already-provisioned cluster.
    #[test]
    fn short_names_are_unchanged_by_the_collision_guard() {
        assert_eq!(
            sanitize_db_name("my-cluster", "k3s_").unwrap(),
            "k3s_my_cluster"
        );
    }
}
