---
description: deploy ui/rust code changes to all pubky-node surfaces
---

# Deploy Changes to All Pubky Node Surfaces

Run after ANY change to `src/`, `src-tauri/`, or `Cargo.toml`.

## 1. Git commit & push
```bash
cd /Volumes/vibedrive/vibes-dev/pubky-node
git add -A && git commit -m "<message>"
git push origin main
```

## 2. Build sidecars (embeds HTML/JS/CSS into the binary)
// turbo
```bash
cd /Volumes/vibedrive/vibes-dev/pubky-node
bash scripts/build-sidecars.sh --release
```
Compiles `pubky-node` (with new embedded dashboard) and `pkdns`, copies to `src-tauri/binaries/`.

## 3. Build & install the macOS Tauri app
// turbo
```bash
cd /Volumes/vibedrive/vibes-dev/pubky-node
cargo tauri build
rm -rf "/Applications/Pubky Node.app"
hdiutil attach "src-tauri/target/release/bundle/dmg/Pubky Node_0.2.0_aarch64.dmg" -nobrowse -quiet
cp -R "/Volumes/Pubky Node/Pubky Node.app" "/Applications/Pubky Node.app"
hdiutil detach "/Volumes/Pubky Node" -quiet
```
> ⚠️ Must `rm -rf` the old `.app` first — macOS `cp -R` silently skips replacing an existing app bundle.

## 4. Relaunch the app — updates BOTH the macOS window AND localhost:9090

> The Tauri app owns the `pubky-node` sidecar process. Closing the window only minimizes to tray.
> Use the tray menu → **Quit Pubky Node**, or run:

// turbo
```bash
osascript -e 'quit app "Pubky Node"'
sleep 2
open "/Applications/Pubky Node.app"
```

## 5. (Optional) Umbrel / Docker
If deployed on Umbrel, pull the latest image or `git pull` on the server.
