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
                cards: vec![
                    CardLayout { id: "stats-row".to_string(), visible: true },
                    CardLayout { id: "health-row".to_string(), visible: true },
                    CardLayout { id: "dht-panel".to_string(), visible: true },
                    CardLayout { id: "relay-panel".to_string(), visible: true },
                ],
            },
            PageLayout {
                id: "vault".to_string(),
                label: "Key Vault".to_string(),
                icon: "🔐".to_string(),
                visible: true,
                cards: vec![
                    CardLayout { id: "vault-keys".to_string(), visible: true },
                    CardLayout { id: "watchlist-panel".to_string(), visible: true },
                ],
            },
            PageLayout {
                id: "profile".to_string(),
                label: "Profile".to_string(),
                icon: "👤".to_string(),
                visible: true,
                cards: vec![
                    CardLayout { id: "profile-editor".to_string(), visible: true },
                ],
            },
            PageLayout {
                id: "homeserver".to_string(),
                label: "Server Dashboard".to_string(),
                icon: "🖥".to_string(),
                visible: true,
                cards: vec![
                    CardLayout { id: "hs-prereqs".to_string(), visible: true },
                    CardLayout { id: "hs-status".to_string(), visible: true },
                    CardLayout { id: "hs-tokens".to_string(), visible: true },
                    CardLayout { id: "hs-config".to_string(), visible: true },
                    CardLayout { id: "hs-pkarr".to_string(), visible: true },
                    CardLayout { id: "hs-logs".to_string(), visible: true },
                ],
            },
            PageLayout {
                id: "networks".to_string(),
                label: "Network Status".to_string(),
                icon: "🌐".to_string(),
                visible: true,
                cards: vec![
                    CardLayout { id: "upnp-card".to_string(), visible: true },
                    CardLayout { id: "tunnel-card".to_string(), visible: true },
                    CardLayout { id: "relay-tunnel-card".to_string(), visible: true },
                    CardLayout { id: "dns-tunnel-card".to_string(), visible: true },
                    CardLayout { id: "proxy-card".to_string(), visible: true },
                    CardLayout { id: "dns-card".to_string(), visible: true },
                    CardLayout { id: "reachability-card".to_string(), visible: true },
                ],
            },
            PageLayout {
                id: "explorer".to_string(),
                label: "Network Explorer".to_string(),
                icon: "🔍".to_string(),
                visible: true,
                cards: vec![
                    CardLayout { id: "explorer-main".to_string(), visible: true },
                ],
            },
            PageLayout {
                id: "publisher".to_string(),
                label: "PKARR Publisher".to_string(),
                icon: "📡".to_string(),
                visible: true,
                cards: vec![
                    CardLayout { id: "publisher-main".to_string(), visible: true },
                ],
            },
            PageLayout {
                id: "vanity".to_string(),
                label: "Vanity Key Gen".to_string(),
                icon: "⭐".to_string(),
                visible: true,
                cards: vec![
                    CardLayout { id: "vanity-main".to_string(), visible: true },
                ],
            },
            PageLayout {
                id: "recovery".to_string(),
                label: "Recovery".to_string(),
                icon: "🔄".to_string(),
                visible: true,
                cards: vec![
                    CardLayout { id: "backup-status".to_string(), visible: true },
                    CardLayout { id: "backup-identities".to_string(), visible: true },
                    CardLayout { id: "snapshots".to_string(), visible: true },
                    CardLayout { id: "migration".to_string(), visible: true },
                ],
            },
            PageLayout {
                id: "guide".to_string(),
                label: "Guide".to_string(),
                icon: "📖".to_string(),
                visible: true,
                cards: vec![
                    CardLayout { id: "guide-content".to_string(), visible: true },
                ],
            },
            PageLayout {
                id: "settings".to_string(),
                label: "Settings".to_string(),
                icon: "⚙️".to_string(),
                visible: true,
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
