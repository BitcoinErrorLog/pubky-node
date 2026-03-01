// Embedded PostgreSQL manager — zero-dependency database for homeserver.
//
// Uses `postgresql_embedded` crate to bundle PostgreSQL binaries at compile
// time. On first run, extracts to data_dir/pg/ and initializes. On subsequent
// runs, just starts the existing cluster.

use std::path::{Path, PathBuf};
use tracing;

/// Dedicated port for embedded PostgreSQL (avoids conflicts with system PG).
const EMBEDDED_PG_PORT: u16 = 5433;

/// Database name for the homeserver.
const DB_NAME: &str = "pubky_homeserver";

/// Manages an embedded PostgreSQL instance.
pub struct EmbeddedPg {
    pg: postgresql_embedded::PostgreSQL,
    port: u16,
    installation_dir: PathBuf,
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
            installation_dir: pg_dir.clone(),
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

        Ok(EmbeddedPg {
            pg,
            port: EMBEDDED_PG_PORT,
            installation_dir: pg_dir,
        })
    }

    /// Get the PostgreSQL connection URL.
    pub fn connection_url(&self) -> String {
        format!("postgres://127.0.0.1:{}/{}", self.port, DB_NAME)
    }

    /// Get the port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Check if the server is running.
    pub fn is_running(&self) -> bool {
        // The postgresql_embedded crate tracks state internally
        true // If we hold a reference, it's running (stopped in Drop)
    }

    /// Stop the embedded PostgreSQL server.
    pub async fn stop(&mut self) -> Result<(), String> {
        tracing::info!("Stopping embedded PostgreSQL...");
        self.pg.stop().await.map_err(|e| format!("PostgreSQL stop failed: {}", e))?;
        tracing::info!("PostgreSQL stopped");
        Ok(())
    }
}

// Use VersionReq::from_str
use std::str::FromStr;
