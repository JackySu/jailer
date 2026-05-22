use anyhow::Result;
use std::process::Command;

pub fn run(me: bool, since: Option<&str>, role: Option<&str>, follow: bool) -> Result<()> {
    let mut args = vec![
        "--output".to_string(),
        "short-precise".to_string(),
        "-t".to_string(),
        "icb-sandbox-audit".to_string(),
    ];

    if follow {
        args.push("-f".to_string());
    }

    if let Some(s) = since {
        args.push("--since".to_string());
        args.push(s.to_string());
    } else {
        args.push("--since".to_string());
        args.push("5min ago".to_string());
    }

    if me {
        let uid = unsafe { libc::getuid() };
        args.push("--output-fields=MESSAGE".to_string());
        // We'll grep for the UID in post-processing
        let output = Command::new("journalctl")
            .args(&args)
            .output()
            .map_err(|e| anyhow::anyhow!("journalctl: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let uid_str = format!("uid={}", uid);
        for line in stdout.lines() {
            if line.contains(&uid_str) {
                if let Some(r) = role {
                    if line.contains(&format!("role={}", r)) {
                        println!("{}", line);
                    }
                } else {
                    println!("{}", line);
                }
            }
        }
    } else if let Some(r) = role {
        let output = Command::new("journalctl")
            .args(&args)
            .output()
            .map_err(|e| anyhow::anyhow!("journalctl: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let role_str = format!("role={}", r);
        for line in stdout.lines() {
            if line.contains(&role_str) {
                println!("{}", line);
            }
        }
    } else if follow {
        let status = Command::new("journalctl")
            .args(&args)
            .status()
            .map_err(|e| anyhow::anyhow!("journalctl: {}", e))?;
        if !status.success() {
            anyhow::bail!("journalctl exited with {}", status);
        }
    } else {
        let output = Command::new("journalctl")
            .args(&args)
            .output()
            .map_err(|e| anyhow::anyhow!("journalctl: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim().is_empty() {
            println!("No audit events in the specified time range.");
        } else {
            print!("{}", stdout);
        }
    }
    Ok(())
}
