//! `pubky-node dns setup` — auto-configure OS DNS for .pkarr/.key resolution.

use clap::Args;

#[derive(Args, Debug)]
pub struct DnsSetupArgs {
    /// Show what would be done without making changes
    #[arg(long)]
    pub dry_run: bool,

    /// Remove the DNS configuration instead of setting it up
    #[arg(long)]
    pub remove: bool,
}

pub fn execute(args: DnsSetupArgs) -> anyhow::Result<()> {
    let platform = detect_platform();

    match platform {
        Platform::MacOS => setup_macos(&args),
        Platform::Linux => setup_linux(&args),
        Platform::Windows => setup_windows(&args),
    }
}

#[derive(Debug, PartialEq)]
enum Platform {
    MacOS,
    Linux,
    Windows,
}

fn detect_platform() -> Platform {
    if cfg!(target_os = "macos") {
        Platform::MacOS
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else {
        Platform::Linux
    }
}

fn setup_macos(args: &DnsSetupArgs) -> anyhow::Result<()> {
    println!("Detected: macOS");
    println!();

    if args.remove {
        println!("Removing .pkarr and .key DNS resolver configuration...");
        if args.dry_run {
            println!("  [dry-run] Would remove /etc/resolver/pkarr");
            println!("  [dry-run] Would remove /etc/resolver/key");
        } else {
            println!("Run the following commands:");
            println!();
            println!("  sudo rm -f /etc/resolver/pkarr /etc/resolver/key");
            println!();
            println!("DNS configuration removed. .pkarr and .key domains will no longer resolve.");
        }
    } else {
        println!("Setting up per-TLD DNS resolution for .pkarr and .key domains...");
        println!();

        if args.dry_run {
            println!("  [dry-run] Would create /etc/resolver/pkarr with: nameserver 127.0.0.1");
            println!("  [dry-run] Would create /etc/resolver/key with: nameserver 127.0.0.1");
        } else {
            println!("Run the following commands:");
            println!();
            println!("  sudo mkdir -p /etc/resolver");
            println!("  echo \"nameserver 127.0.0.1\" | sudo tee /etc/resolver/pkarr");
            println!("  echo \"nameserver 127.0.0.1\" | sudo tee /etc/resolver/key");
            println!();
            println!("This only routes .pkarr and .key queries to your local pkdns.");
            println!("All other DNS is completely unaffected.");
        }
    }

    Ok(())
}

fn setup_linux(args: &DnsSetupArgs) -> anyhow::Result<()> {
    println!("Detected: Linux");
    println!();

    if args.remove {
        println!("Removing systemd-resolved configuration...");
        if args.dry_run {
            println!("  [dry-run] Would remove /etc/systemd/resolved.conf.d/pubky.conf");
        } else {
            println!("Run the following commands:");
            println!();
            println!("  sudo rm -f /etc/systemd/resolved.conf.d/pubky.conf");
            println!("  sudo systemctl restart systemd-resolved");
        }
    } else {
        println!("Setting up systemd-resolved for .pkarr and .key domains...");
        println!();

        if args.dry_run {
            println!("  [dry-run] Would create /etc/systemd/resolved.conf.d/pubky.conf");
            println!("  [dry-run] Contents: [Resolve]\\nDNS=127.0.0.1\\nDomains=~pkarr ~key");
        } else {
            println!("Run the following commands:");
            println!();
            println!("  sudo mkdir -p /etc/systemd/resolved.conf.d");
            println!("  sudo tee /etc/systemd/resolved.conf.d/pubky.conf <<EOF");
            println!("  [Resolve]");
            println!("  DNS=127.0.0.1");
            println!("  Domains=~pkarr ~key");
            println!("  EOF");
            println!("  sudo systemctl restart systemd-resolved");
        }
    }

    Ok(())
}

fn setup_windows(args: &DnsSetupArgs) -> anyhow::Result<()> {
    println!("Detected: Windows");
    println!();

    if args.remove {
        println!("To remove the DNS configuration:");
        println!();
        println!("  1. Settings → Network & Internet → Wi-Fi/Ethernet");
        println!("  2. Click your connection → DNS server assignment → Edit");
        println!("  3. Change back to Automatic (DHCP)");
        println!("  4. Save");
    } else if args.dry_run {
        println!("  [dry-run] Would instruct user to set DNS to 127.0.0.1");
    } else {
        println!("Automatic DNS setup is not supported on Windows.");
        println!("Please configure manually:");
        println!();
        println!("  1. Settings → Network & Internet → Wi-Fi/Ethernet");
        println!("  2. Click your connection → DNS server assignment → Edit");
        println!("  3. Set Preferred DNS to: 127.0.0.1");
        println!("  4. Set Alternate DNS to: 8.8.8.8 (fallback)");
        println!("  5. Save");
        println!();
        println!("Also disable Secure DNS in your browser:");
        println!("  Chrome/Edge: Settings → Privacy & Security → Use Secure DNS → Off");
        println!("  Firefox: Settings → Privacy → DNS over HTTPS → Off");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_platform() {
        let platform = detect_platform();
        #[cfg(target_os = "macos")]
        assert_eq!(platform, Platform::MacOS);
        #[cfg(target_os = "linux")]
        assert_eq!(platform, Platform::Linux);
        #[cfg(target_os = "windows")]
        assert_eq!(platform, Platform::Windows);
    }

    #[test]
    fn test_setup_macos_dry_run() {
        let args = DnsSetupArgs {
            dry_run: true,
            remove: false,
        };
        // Should not panic
        setup_macos(&args).unwrap();
    }

    #[test]
    fn test_setup_linux_dry_run() {
        let args = DnsSetupArgs {
            dry_run: true,
            remove: false,
        };
        setup_linux(&args).unwrap();
    }

    #[test]
    fn test_setup_remove_dry_run() {
        let args = DnsSetupArgs {
            dry_run: true,
            remove: true,
        };
        setup_macos(&args).unwrap();
        setup_linux(&args).unwrap();
        setup_windows(&args).unwrap();
    }
}
