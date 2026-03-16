//! Layout configuration — customizable dashboard page/card arrangement.
//!
//! Persisted to `{data_dir}/layout.json`. If missing, `default_layout()` is used.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// A single card within a page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardLayout {
    /// Unique card identifier (matches HTML `data-card-id`)
    pub id: String,
    /// Whether the card is visible
    pub visible: bool,
}

/// A single page (tab) in the sidebar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageLayout {
    /// Unique page identifier (matches tab `data-tab` attribute)
    pub id: String,
    /// Display label shown in sidebar and header
    pub label: String,
    /// Emoji or icon string
    pub icon: String,
    /// Whether the page is visible in the sidebar
    pub visible: bool,
    /// Category group label shown in sidebar (e.g. "Overview", "My Identity")
    #[serde(default)]
    pub category: Option<String>,
    /// Ordered list of cards on this page
    pub cards: Vec<CardLayout>,
}

/// Root layout configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layout {
    /// Schema version for future migrations
    pub version: u32,
    /// Ordered list of pages
    pub pages: Vec<PageLayout>,
}

impl Layout {
    /// Merge a saved layout with the default, preserving user customizations
    /// but ensuring new cards/pages added in updates appear.
    pub fn merge_with_default(mut self) -> Self {
        let default = default_layout();

        // Add any new pages from default that the user doesn't have
        for dp in &default.pages {
            if !self.pages.iter().any(|p| p.id == dp.id) {
                self.pages.push(dp.clone());
            }
        }

        // For each page, add any new cards from default that the user doesn't have
        for page in &mut self.pages {
            if let Some(dp) = default.pages.iter().find(|p| p.id == page.id) {
                for dc in &dp.cards {
                    if !page.cards.iter().any(|c| c.id == dc.id) {
                        page.cards.push(dc.clone());
                    }
                }
            }
        }

        self
    }
}

/// Load layout from data directory, falling back to default.
pub fn load_layout(data_dir: &Path) -> Layout {
    let path = data_dir.join("layout.json");
    if path.exists() {
        match std::fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<Layout>(&contents) {
                Ok(layout) => return layout.merge_with_default(),
                Err(e) => {
                    tracing::warn!("Invalid layout.json, using default: {}", e);
                }
            },
            Err(e) => {
                tracing::warn!("Could not read layout.json, using default: {}", e);
            }
        }
    }
    default_layout()
}

/// Save layout to data directory.
pub fn save_layout(data_dir: &Path, layout: &Layout) -> anyhow::Result<()> {
    let path = data_dir.join("layout.json");
    let json = serde_json::to_string_pretty(layout)?;
    std::fs::write(&path, json)?;
    Ok(())
}

/// Reset layout to default by deleting the custom file.
pub fn reset_layout(data_dir: &Path) -> Layout {
    let path = data_dir.join("layout.json");
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
    default_layout()
}

/// The built-in default layout matching the current dashboard structure.
pub fn default_layout() -> Layout {
    Layout {
        version: 1,
        pages: vec![
            PageLayout {
                id: "dashboard".to_string(),
                label: "Dashboard".to_string(),
                icon: "📊".to_string(),
                visible: true,
                category: Some("Overview".to_string()),
                cards: vec![
                    CardLayout { id: "stats-row".to_string(), visible: true },
                    CardLayout { id: "health-row".to_string(), visible: true },
                    CardLayout { id: "dht-panel".to_string(), visible: true },
                    CardLayout { id: "relay-panel".to_string(), visible: true },
                ],
            },
            PageLayout {
                id: "vault".to_string(),
                label: "Keychain".to_string(),
                icon: "🔐".to_string(),
                visible: true,
                category: Some("My Identity".to_string()),
                cards: vec![
                    CardLayout { id: "vault-panel".to_string(), visible: true },
                    CardLayout { id: "watchlist-panel".to_string(), visible: true },
                    CardLayout { id: "vanity-panel".to_string(), visible: true },
                ],
            },
            PageLayout {
                id: "profile".to_string(),
                label: "Profile".to_string(),
                icon: "👤".to_string(),
                visible: true,
                category: None,
                cards: vec![
                    CardLayout { id: "hs-profile-panel".to_string(), visible: true },
                ],
            },
            PageLayout {
                id: "homeserver".to_string(),
                label: "Server Dashboard".to_string(),
                icon: "🖥".to_string(),
                visible: true,
                category: Some("My Homeserver".to_string()),
                cards: vec![
                    CardLayout { id: "hs-control-panel".to_string(), visible: true },
                    CardLayout { id: "hs-invite-panel".to_string(), visible: true },
                    CardLayout { id: "hs-config-panel".to_string(), visible: true },
                    CardLayout { id: "hs-pkarr-panel".to_string(), visible: true },
                    CardLayout { id: "hs-logs-panel".to_string(), visible: true },
                    CardLayout { id: "hs-users-panel".to_string(), visible: true },
                    CardLayout { id: "hs-identity-panel".to_string(), visible: true },
                    CardLayout { id: "hs-files-panel".to_string(), visible: true },
                    CardLayout { id: "hs-api-panel".to_string(), visible: true },
                ],
            },
            PageLayout {
                id: "network".to_string(),
                label: "Network Status".to_string(),
                icon: "🌐".to_string(),
                visible: true,
                category: Some("Node & Network".to_string()),
                cards: vec![
                    CardLayout { id: "upnp-panel".to_string(), visible: true },
                    CardLayout { id: "hs-tunnel-panel".to_string(), visible: true },
                    CardLayout { id: "relay-tunnel-panel".to_string(), visible: true },
                    CardLayout { id: "dns-tunnel-panel".to_string(), visible: true },
                    CardLayout { id: "proxy-panel".to_string(), visible: true },
                    CardLayout { id: "dns-panel".to_string(), visible: true },
                ],
            },
            PageLayout {
                id: "explorer".to_string(),
                label: "Network Explorer".to_string(),
                icon: "🔍".to_string(),
                visible: true,
                category: Some("Tools".to_string()),
                cards: vec![
                    CardLayout { id: "explorer-main".to_string(), visible: true },
                ],
            },
            PageLayout {
                id: "publisher".to_string(),
                label: "PKARR Publisher".to_string(),
                icon: "📡".to_string(),
                visible: true,
                category: None,
                cards: vec![
                    CardLayout { id: "publisher-panel".to_string(), visible: true },
                ],
            },

            PageLayout {
                id: "recovery".to_string(),
                label: "Recovery".to_string(),
                icon: "🔄".to_string(),
                visible: true,
                category: Some("System".to_string()),
                cards: vec![
                    CardLayout { id: "backup-status-panel".to_string(), visible: true },
                    CardLayout { id: "backup-identities-panel".to_string(), visible: true },
                    CardLayout { id: "backup-snapshots-panel".to_string(), visible: true },
                    CardLayout { id: "migration-panel".to_string(), visible: true },
                    CardLayout { id: "backup-export-panel".to_string(), visible: true },
                    CardLayout { id: "backup-verify-panel".to_string(), visible: true },
                ],
            },
            PageLayout {
                id: "guide".to_string(),
                label: "Guide".to_string(),
                icon: "📖".to_string(),
                visible: true,
                category: None,
                cards: vec![
                    CardLayout { id: "guide-content".to_string(), visible: true },
                ],
            },
            PageLayout {
                id: "settings".to_string(),
                label: "Settings".to_string(),
                icon: "⚙️".to_string(),
                visible: true,
                category: None,
                cards: vec![
                    CardLayout { id: "settings-password".to_string(), visible: true },
                    CardLayout { id: "settings-storage".to_string(), visible: true },
                    CardLayout { id: "settings-controls".to_string(), visible: true },
                    CardLayout { id: "settings-about".to_string(), visible: true },
                ],
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_layout_has_all_pages() {
        let layout = default_layout();
        assert!(layout.pages.len() >= 10);
        assert!(layout.pages.iter().any(|p| p.id == "dashboard"));
        assert!(layout.pages.iter().any(|p| p.id == "vault"));
        assert!(layout.pages.iter().any(|p| p.id == "settings"));
    }

    #[test]
    fn test_serialize_round_trip() {
        let layout = default_layout();
        let json = serde_json::to_string(&layout).unwrap();
        let parsed: Layout = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.pages.len(), layout.pages.len());
    }

    #[test]
    fn test_merge_adds_new_pages() {
        let mut layout = default_layout();
        layout.pages.retain(|p| p.id != "settings");
        let merged = layout.merge_with_default();
        assert!(merged.pages.iter().any(|p| p.id == "settings"));
    }

    #[test]
    fn test_merge_preserves_user_order() {
        let mut layout = default_layout();
        // Move settings to first position
        let settings_idx = layout.pages.iter().position(|p| p.id == "settings").unwrap();
        let settings = layout.pages.remove(settings_idx);
        layout.pages.insert(0, settings);
        let merged = layout.merge_with_default();
        assert_eq!(merged.pages[0].id, "settings");
    }
}
