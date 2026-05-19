use anyhow::{bail, Result};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

const SOCKET_PATH: &str = "/run/bpfjailer/enrollment.sock";

pub fn run(policy: Option<String>, cgroup: Option<String>, cmd: Vec<String>) -> Result<()> {
    let _ = policy; // reserved for future use
    let _ = cgroup; // daemon decides the cgroup now

    // Guard: refuse to nest
    let my_cg = current_cgroup()?;
    if my_cg.starts_with("/bpfjailer/") {
        bail!(
            "Already inside a jailed shell (cgroup={}). Exit first.",
            my_cg
        );
    }

    // Check daemon is running
    if !Path::new(SOCKET_PATH).exists() {
        bail!(
            "Daemon not running (no socket at {}). Start it first:\n  \
             sudo systemctl start bpfjailer-daemon",
            SOCKET_PATH
        );
    }

    // Ask daemon to enroll our PID into the cgroup
    eprintln!("[jailerctl] requesting enrollment from daemon...");
    let enrolled_cgroup = enroll_via_socket("code_agent")?;
    eprintln!("[jailerctl] enrolled: ok ({})", enrolled_cgroup);

    // Verify via /proc/self/cgroup
    let new_cg = current_cgroup()?;
    if !new_cg.starts_with("/bpfjailer/") {
        bail!(
            "Cgroup join failed: expected /bpfjailer/..., got {}",
            new_cg
        );
    }

    // Determine command to exec
    let (program, args) = if cmd.is_empty() {
        ("bash".to_string(), vec!["--login".to_string()])
    } else {
        let mut iter = cmd.into_iter();
        let prog = iter.next().unwrap();
        let rest: Vec<String> = iter.collect();
        (prog, rest)
    };

    eprintln!("[jailerctl] exec: {} {}", program, args.join(" "));

    // exec replaces this process — the new process inherits the cgroup
    let err = Command::new(&program)
        .args(&args)
        .env("BPFJAILER_ROLE", "code_agent")
        .exec();

    bail!("exec failed: {}", err);
}

/// Connect to the daemon socket and send an EnrollSelf request.
/// Returns the cgroup path on success.
fn enroll_via_socket(role: &str) -> Result<String> {
    let mut stream = UnixStream::connect(SOCKET_PATH)
        .map_err(|e| anyhow::anyhow!(
            "cannot connect to {}: {}. Are you in the 'bpfjailer' group?",
            SOCKET_PATH, e
        ))?;

    let request = serde_json::json!({
        "EnrollSelf": { "role": role }
    });
    let mut msg = serde_json::to_string(&request)?;
    msg.push('\n');
    stream.write_all(msg.as_bytes())?;
    stream.flush()?;

    // Shutdown write side so daemon knows we're done sending
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut reader = BufReader::new(&stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line)?;

    let resp: serde_json::Value = serde_json::from_str(&response_line)
        .map_err(|e| anyhow::anyhow!("invalid response from daemon: {}", e))?;

    if let Some(cgroup) = resp.get("Enrolled").and_then(|v| v.get("cgroup")).and_then(|v| v.as_str()) {
        Ok(cgroup.to_string())
    } else if let Some(err) = resp.get("Error").and_then(|v| v.as_str()) {
        bail!("daemon refused enrollment: {}", err);
    } else {
        bail!("unexpected response from daemon: {}", response_line.trim());
    }
}

fn current_cgroup() -> Result<String> {
    let content = fs::read_to_string("/proc/self/cgroup")?;
    for line in content.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() == 3 && parts[1].is_empty() {
            return Ok(parts[2].to_string());
        }
    }
    bail!("Could not determine current cgroup from /proc/self/cgroup");
}
