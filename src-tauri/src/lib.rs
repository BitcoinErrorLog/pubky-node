//! Pubky Node desktop app — Tauri v2 wrapper.
//!
//! Launches pubky-node as a sidecar binary, displays the dashboard
//! in a native webview, and provides a system tray for background operation.

use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::TrayIconBuilder,
    Manager, WindowEvent,
};
use tauri_plugin_shell::ShellExt;
use tauri_plugin_shell::process::CommandEvent;

/// Dashboard URL served by the pubky-node sidecar.
const DASHBOARD_URL: &str = "http://localhost:9090";
const HEALTH_URL: &str = "http://localhost:9090/health";

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            // --- System Tray ---
            let open_i = MenuItem::with_id(app, "open", "Open Dashboard", true, None::<&str>)?;
            let separator = PredefinedMenuItem::separator(app)?;
            let quit_i = MenuItem::with_id(app, "quit", "Quit Pubky Node", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open_i, &separator, &quit_i])?;

            let _tray = TrayIconBuilder::new()
                .menu(&menu)
                .show_menu_on_left_click(true)
                .tooltip("Pubky Node")
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "quit" => {
                        app.exit(0);
                    }
                    _ => {}
                })
                .build(app)?;

            // --- Spawn pubky-node sidecar ---
            let app_handle = app.handle().clone();
            let sidecar_command = app_handle
                .shell()
                .sidecar("pubky-node")
                .unwrap()
                .args([
                    "--dashboard-bind", "127.0.0.1",
                    "--dashboard-port", "9090",
                ]);

            let (mut rx, _child) = sidecar_command
                .spawn()
                .expect("Failed to spawn pubky-node sidecar");

            // Log sidecar output
            tauri::async_runtime::spawn(async move {
                while let Some(event) = rx.recv().await {
                    match event {
                        CommandEvent::Stdout(line) => {
                            let text = String::from_utf8_lossy(&line);
                            println!("[pubky-node] {}", text.trim());
                        }
                        CommandEvent::Stderr(line) => {
                            let text = String::from_utf8_lossy(&line);
                            eprintln!("[pubky-node] {}", text.trim());
                        }
                        CommandEvent::Terminated(status) => {
                            eprintln!("[pubky-node] process exited: {:?}", status);
                            break;
                        }
                        _ => {}
                    }
                }
            });

            // --- Wait for health check, then navigate to dashboard ---
            let app_handle2 = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                // Poll health endpoint
                let client = reqwest::Client::new();
                let mut ready = false;
                for _ in 0..30 {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    if let Ok(resp) = client.get(HEALTH_URL).send().await {
                        if resp.status().is_success() {
                            ready = true;
                            break;
                        }
                    }
                }

                if ready {
                    if let Some(window) = app_handle2.get_webview_window("main") {
                        let _ = window.eval(&format!(
                            "window.location.replace('{}')",
                            DASHBOARD_URL
                        ));
                    }
                } else {
                    if let Some(window) = app_handle2.get_webview_window("main") {
                        let _ = window.eval(
                            "document.getElementById('status').textContent = \
                             'Failed to start pubky-node. Check logs for details.';\
                             document.getElementById('status').style.color = '#ef4444';"
                        );
                    }
                }
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            // Minimize to tray on close instead of quitting
            if let WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
