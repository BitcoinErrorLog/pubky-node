use std::process::Stdio;

use tokio::process::{Child, Command};
use tracing::{error, info, warn};

use crate::config::Config;

/// Manages the pkdns subprocess.
pub struct DnsProcess {
    child: Child,
}

impl DnsProcess {
    /// Spawns pkdns as a child process.
    pub async fn start(config: &Config) -> anyhow::Result<Option<Self>> {
        if !config.dns.enabled {
            info!("DNS resolver is disabled in config");
            return Ok(None);
        }

        let binary = config
            .dns
            .binary
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "pkdns".to_string());

        // Build CLI args for pkdns
        let mut args: Vec<String> = Vec::new();

        args.push("--forward".to_string());
        args.push(config.dns.forward.clone());

        if let Some(ref pkdns_dir) = config.dns.pkdns_dir {
            args.push("--pkdns-dir".to_string());
            args.push(pkdns_dir.to_string_lossy().to_string());
        }

        info!(
            "Starting pkdns subprocess: {} {}",
            binary,
            args.join(" ")
        );

        let child = match Command::new(&binary)
            .args(&args)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    warn!(
                        "pkdns binary not found at '{}'. DNS resolution disabled. \
                         Install pkdns or set dns.binary in config.",
                        binary
                    );
                    return Ok(None);
                }
                return Err(e.into());
            }
        };

        info!("pkdns subprocess started (pid: {:?})", child.id());

        Ok(Some(Self { child }))
    }

    /// Gracefully shuts down the pkdns subprocess.
    pub async fn shutdown(&mut self) {
        info!("Shutting down pkdns subprocess...");
        if let Some(id) = self.child.id() {
            // Send SIGTERM on Unix
            #[cfg(unix)]
            {
                unsafe {
                    libc::kill(id as i32, libc::SIGTERM);
                }
            }
            // On non-Unix, just kill it
            #[cfg(not(unix))]
            {
                let _ = self.child.kill().await;
            }

            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.child.wait(),
            )
            .await
            {
                Ok(Ok(status)) => info!("pkdns exited with: {}", status),
                Ok(Err(e)) => error!("Error waiting for pkdns: {}", e),
                Err(_) => {
                    warn!("pkdns didn't exit in time, killing...");
                    let _ = self.child.kill().await;
                }
            }
        }
    }
}
