// Embedded PostgreSQL manager — zero-dependency database for homeserver.
//
// Uses `postgresql_embedded` crate to bundle PostgreSQL binaries at compile
// time. On first run, extracts to data_dir/pg/ and initializes. On subsequent
// runs, just starts the existing cluster.

use std::path::Path;
use std::str::FromStr;

/// Dedicated port for embedded PostgreSQL (avoids conflicts with system PG).
const EMBEDDED_PG_PORT: u16 = 5433;

/// Database name for the homeserver.
const DB_NAME: &str = "pubky_homeserver";

/// Manages an embedded PostgreSQL instance.
/// Holding this struct keeps the PostgreSQL server running.
/// Dropping it stops the server (via the crate's Drop implementation).
#[allow(dead_code)]
pub struct EmbeddedPg {
    pg: postgresql_embedded::PostgreSQL,
}

impl EmbeddedPg {
    /// Start the embedded PostgreSQL server.
    ///
    /// On first run: extracts bundled PG binaries, runs initdb, starts server,
    /// creates the database. On subsequent runs: just starts the server.
    pub async fn start(data_dir: &Path) -> Result<Self, String> {
        let pg_dir = data_dir.join("pg");

        tracing::info!("Starting embedded PostgreSQL (data: {})", pg_dir.display());

        let settings = postgresql_embedded::Settings {
            version: postgresql_embedded::VersionReq::from_str("=17.4.0")
                .unwrap_or(postgresql_embedded::VersionReq::STAR),
            port: EMBEDDED_PG_PORT,
            temporary: false,
            installation_dir: pg_dir,
            ..Default::default()
        };

        let mut pg = postgresql_embedded::PostgreSQL::new(settings);

        // Setup: extracts bundled binaries on first run, no-op after that
        pg.setup().await.map_err(|e| format!("PostgreSQL setup failed: {}", e))?;
        tracing::info!("PostgreSQL binaries ready");

        // Start the server
        pg.start().await.map_err(|e| format!("PostgreSQL start failed: {}", e))?;
        tracing::info!("PostgreSQL started on port {}", EMBEDDED_PG_PORT);

        // Create database if it doesn't exist
        match pg.database_exists(DB_NAME).await {
            Ok(true) => {
                tracing::info!("Database '{}' already exists", DB_NAME);
            }
            Ok(false) => {
                pg.create_database(DB_NAME).await
                    .map_err(|e| format!("Failed to create database '{}': {}", DB_NAME, e))?;
                tracing::info!("Database '{}' created", DB_NAME);
            }
            Err(e) => {
                // If we can't check, try to create (it'll fail gracefully if exists)
                tracing::warn!("Could not check database existence: {}, attempting create", e);
                let _ = pg.create_database(DB_NAME).await;
            }
        }

        Ok(EmbeddedPg { pg })
    }

    /// Get the PostgreSQL connection URL.
    pub fn connection_url(&self) -> String {
        format!("postgres://127.0.0.1:{}/{}", EMBEDDED_PG_PORT, DB_NAME)
    }

    /// Stop the embedded PostgreSQL server.
    #[allow(dead_code)]
    pub async fn stop(&mut self) -> Result<(), String> {
        tracing::info!("Stopping embedded PostgreSQL...");
        self.pg.stop().await.map_err(|e| format!("PostgreSQL stop failed: {}", e))?;
        tracing::info!("PostgreSQL stopped");
        Ok(())
    }
}
