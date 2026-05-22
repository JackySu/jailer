use anyhow::{bail, Result};
use std::fs;
use std::path::Path;
use std::process::Command;

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

const DAEMON_BIN: &str = "/usr/sbin/icb-sandboxd";
const CTL_BIN: &str = "/usr/bin/icb-sandbox-ctl";
const BOOTSTRAP_BIN: &str = "/usr/bin/icb-sandbox-bootstrap";
const SERVICE_DAEMON: &str = "/etc/systemd/system/icb-sandboxd.service";
const SERVICE_BOOTSTRAP: &str = "/etc/systemd/system/icb-sandbox-bootstrap.service";
const RUN_DIR: &str = "/run/icb-sandbox";
const BPF_PIN: &str = "/sys/fs/bpf/icb-sandbox";
const LIB_DIR: &str = "/usr/lib/icb-sandbox";
const CONFIG_DIR: &str = "/etc/icb/sandbox";

pub fn run(purge: bool) -> Result<()> {
    if !is_root() {
        bail!("uninstall requires root. Run with sudo.");
    }

    println!("Stopping icb-sandboxd...");
    let _ = Command::new("systemctl").args(["stop", "icb-sandboxd"]).status();
    let _ = Command::new("systemctl").args(["stop", "icb-sandbox-bootstrap"]).status();

    println!("Disabling services...");
    let _ = Command::new("systemctl").args(["disable", "icb-sandboxd"]).status();
    let _ = Command::new("systemctl").args(["disable", "icb-sandbox-bootstrap"]).status();

    println!("Removing binaries...");
    remove_if_exists(DAEMON_BIN);
    remove_if_exists(CTL_BIN);
    remove_if_exists(BOOTSTRAP_BIN);

    println!("Removing systemd units...");
    remove_if_exists(SERVICE_DAEMON);
    remove_if_exists(SERVICE_BOOTSTRAP);
    let _ = Command::new("systemctl").arg("daemon-reload").status();

    println!("Cleaning runtime state...");
    remove_dir_if_exists(RUN_DIR);
    remove_dir_if_exists(BPF_PIN);
    remove_dir_if_exists(LIB_DIR);

    if purge {
        println!("Purging configuration...");
        remove_dir_if_exists(CONFIG_DIR);
    } else {
        println!("Config preserved at {}. Use --purge to remove.", CONFIG_DIR);
    }

    println!("icb-sandbox uninstalled.");
    Ok(())
}

fn remove_if_exists(path: &str) {
    if Path::new(path).exists() {
        if let Err(e) = fs::remove_file(path) {
            eprintln!("  warning: could not remove {}: {}", path, e);
        }
    }
}

fn remove_dir_if_exists(path: &str) {
    if Path::new(path).exists() {
        if let Err(e) = fs::remove_dir_all(path) {
            eprintln!("  warning: could not remove {}: {}", path, e);
        }
    }
}
