//! `pubky-node proxy-hosts` — configure /etc/hosts for .pkarr proxy.

use clap::Args;

const HOSTS_MARKER_BEGIN: &str = "# BEGIN PUBKY-NODE PROXY";
const HOSTS_MARKER_END: &str = "# END PUBKY-NODE PROXY";
const HOSTS_FILE: &str = "/etc/hosts";

#[derive(Args, Debug)]
pub struct ProxyHostsArgs {
    /// Reset (remove) proxy entries instead of adding them
    #[arg(long)]
    pub reset: bool,

    /// Public keys to add (ignored when --reset)
    pub keys: Vec<String>,

    /// Port the proxy listens on
    #[arg(long, default_value_t = 9091)]
    pub port: u16,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn execute(args: ProxyHostsArgs) -> anyhow::Result<()> {
    let hosts = std::fs::read_to_string(HOSTS_FILE).unwrap_or_default();
    let cleaned = remove_block(&hosts);

    if args.reset {
        write_hosts(&cleaned)?;
        if args.json {
            println!("{}", serde_json::json!({ "action": "reset", "success": true }));
        } else {
            eprintln!("✅ Removed proxy entries from {}", HOSTS_FILE);
        }
        return Ok(());
    }

    if args.keys.is_empty() {
        anyhow::bail!("No keys provided. Usage: pubky-node proxy-hosts <KEY1> [KEY2] ...");
    }

    // Build entries
    let mut entries = vec![HOSTS_MARKER_BEGIN.to_string()];
    for key in &args.keys {
        for tld in &["pkarr", "key", "pubky"] {
            entries.push(format!("127.0.0.1 {}.{}", key, tld));
        }
    }
    entries.push(HOSTS_MARKER_END.to_string());

    let block = entries.join("\n");
    let new_hosts = format!("{}\n\n{}\n", cleaned.trim_end(), block);
    write_hosts(&new_hosts)?;

    let count = args.keys.len() * 3;
    if args.json {
        println!("{}", serde_json::json!({
            "action": "setup",
            "success": true,
            "entries": count,
            "keys": args.keys,
        }));
    } else {
        eprintln!("✅ Added {} host entries for {} keys", count, args.keys.len());
        eprintln!("   Proxy: http://<key>.pkarr:{}/", args.port);
    }

    Ok(())
}

fn remove_block(hosts: &str) -> String {
    let mut result = String::new();
    let mut in_block = false;
    for line in hosts.lines() {
        if line.trim() == HOSTS_MARKER_BEGIN {
            in_block = true;
            continue;
        }
        if line.trim() == HOSTS_MARKER_END {
            in_block = false;
            continue;
        }
        if !in_block {
            result.push_str(line);
            result.push('\n');
        }
    }
    result
}

fn write_hosts(content: &str) -> anyhow::Result<()> {
    // Try direct write first, fall back to sudo
    if std::fs::write(HOSTS_FILE, content).is_ok() {
        flush_dns();
        return Ok(());
    }

    // Use sudo via osascript on macOS
    let escaped = content
        .replace('\\', "\\\\")
        .replace('\'', "'\\''")
        .replace('"', "\\\"");
    let script = format!(
        "do shell script \"echo '{}' | sudo tee {} > /dev/null\" with administrator privileges",
        escaped, HOSTS_FILE
    );

    let output = std::process::Command::new("osascript")
        .args(["-e", &script])
        .output()?;

    if !output.status.success() {
        anyhow::bail!(
            "Failed to write {}: {}",
            HOSTS_FILE,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    flush_dns();
    Ok(())
}

fn flush_dns() {
    let _ = std::process::Command::new("dscacheutil")
        .args(["-flushcache"])
        .output();
}
