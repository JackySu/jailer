use anyhow::{bail, Result};
use std::fs;
use std::path::Path;
use std::process::Command;

struct Check {
    name: &'static str,
    pass: bool,
    detail: String,
}

pub fn run() -> Result<()> {
    let mut checks: Vec<Check> = Vec::new();

    checks.push(check_kernel_version());
    checks.push(check_bpf_lsm_enabled());
    checks.push(check_bpf_lsm_boot_param());
    checks.push(check_btf_available());
    checks.push(check_cgroup_v2());
    checks.push(check_daemon_running());
    checks.push(check_disabled_sentinel());

    println!("jailerctl doctor — system readiness check\n");

    let mut all_pass = true;
    for c in &checks {
        let icon = if c.pass { "\x1b[32m✓\x1b[0m" } else { "\x1b[31m✗\x1b[0m" };
        println!("  {} {}: {}", icon, c.name, c.detail);
        if !c.pass {
            all_pass = false;
        }
    }

    println!();
    if all_pass {
        println!("\x1b[32mAll checks passed.\x1b[0m Ready to run bpfjailer.");
    } else {
        println!("\x1b[31mSome checks failed.\x1b[0m Fix the issues above before running bpfjailer.");
        bail!("doctor failed");
    }
    Ok(())
}

fn check_kernel_version() -> Check {
    let name = "Kernel >= 5.11";
    let uname = nix::sys::utsname::uname();
    match uname {
        Ok(u) => {
            let release = u.release().to_string_lossy().to_string();
            let parts: Vec<&str> = release.split('.').collect();
            let (major, minor) = match (parts.first(), parts.get(1)) {
                (Some(a), Some(b)) => {
                    (a.parse::<u32>().unwrap_or(0), b.parse::<u32>().unwrap_or(0))
                }
                _ => (0, 0),
            };
            let pass = major > 5 || (major == 5 && minor >= 11);
            Check {
                name,
                pass,
                detail: format!("{} (need 5.11+)", release),
            }
        }
        Err(_) => Check {
            name,
            pass: false,
            detail: "failed to read uname".into(),
        },
    }
}

fn check_bpf_lsm_enabled() -> Check {
    let name = "CONFIG_BPF_LSM";
    let lsm_path = Path::new("/sys/kernel/security/lsm");
    match fs::read_to_string(lsm_path) {
        Ok(content) => {
            let has_bpf = content.split(',').any(|s| s.trim() == "bpf");
            Check {
                name,
                pass: has_bpf,
                detail: if has_bpf {
                    format!("bpf found in active LSMs ({})", content.trim())
                } else {
                    format!(
                        "bpf NOT in active LSMs ({}). Add lsm=...,bpf to kernel cmdline.",
                        content.trim()
                    )
                },
            }
        }
        Err(e) => Check {
            name,
            pass: false,
            detail: format!("cannot read {}: {}", lsm_path.display(), e),
        },
    }
}

fn check_bpf_lsm_boot_param() -> Check {
    let name = "Boot param lsm=bpf";
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let has_lsm_bpf = cmdline.split_whitespace().any(|arg| {
        arg.starts_with("lsm=") && arg.split('=').nth(1).map_or(false, |v| v.split(',').any(|s| s == "bpf"))
    });
    if has_lsm_bpf {
        Check { name, pass: true, detail: "lsm= includes bpf".into() }
    } else {
        let lsm_active = fs::read_to_string("/sys/kernel/security/lsm")
            .map(|s| s.contains("bpf"))
            .unwrap_or(false);
        if lsm_active {
            Check { name, pass: true, detail: "bpf LSM active (built-in or default)".into() }
        } else {
            Check { name, pass: false, detail: "lsm= does not include bpf in /proc/cmdline".into() }
        }
    }
}

fn check_btf_available() -> Check {
    let name = "BTF (vmlinux)";
    let path = Path::new("/sys/kernel/btf/vmlinux");
    Check {
        name,
        pass: path.exists(),
        detail: if path.exists() {
            "/sys/kernel/btf/vmlinux present".into()
        } else {
            "missing — kernel needs CONFIG_DEBUG_INFO_BTF=y".into()
        },
    }
}

fn check_cgroup_v2() -> Check {
    let name = "cgroup v2 unified";
    let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();
    let has_cgroup2 = mounts.lines().any(|l| l.contains("cgroup2") && l.contains("/sys/fs/cgroup"));
    Check {
        name,
        pass: has_cgroup2,
        detail: if has_cgroup2 {
            "/sys/fs/cgroup is cgroup2".into()
        } else {
            "cgroup v2 unified hierarchy not found at /sys/fs/cgroup".into()
        },
    }
}

fn check_daemon_running() -> Check {
    let name = "Daemon running";
    let socket = Path::new("/run/bpfjailer/enrollment.sock");
    if socket.exists() {
        let pid = Command::new("pidof")
            .arg("bpfjailer-daemon")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default();
        let pid_trimmed = pid.trim();
        let via_systemd = Command::new("systemctl")
            .args(["is-active", "bpfjailer-daemon"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        let detail = if via_systemd {
            format!("pid={} (systemd, logs: journalctl -u bpfjailer-daemon)", pid_trimmed)
        } else {
            format!("pid={} (manual, logs: stderr or /tmp/bpfjailer-daemon.log)", pid_trimmed)
        };
        Check { name, pass: true, detail }
    } else {
        Check {
            name,
            pass: false,
            detail: "no socket at /run/bpfjailer/enrollment.sock".into(),
        }
    }
}

fn check_disabled_sentinel() -> Check {
    let name = "Emergency disable";
    let sentinel = Path::new("/etc/bpfjailer/disabled");
    if sentinel.exists() {
        Check {
            name,
            pass: false,
            detail: format!("{} EXISTS — enforcement is OFF", sentinel.display()),
        }
    } else {
        Check {
            name,
            pass: true,
            detail: "not active (normal operation)".into(),
        }
    }
}
