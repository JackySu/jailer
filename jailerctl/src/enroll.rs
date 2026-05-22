use anyhow::{bail, Result};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

const SOCKET_PATH: &str = "/run/icb-sandbox/enrollment.sock";

pub fn run(pid: u32, role: &str) -> Result<()> {
    let mut stream = UnixStream::connect(SOCKET_PATH).map_err(|e| {
        anyhow::anyhow!(
            "cannot connect to {}: {}. Is the daemon running?",
            SOCKET_PATH,
            e
        )
    })?;

    let request = serde_json::json!({
        "EnrollSelf": { "role": role }
    });

    // If enrolling another PID, use the Enroll variant with lookup
    let request = if pid == std::process::id() {
        request
    } else {
        // For enrolling other PIDs, we need pod_id/role_id.
        // Use Query first to check, then Enroll with a generated pod_id.
        serde_json::json!({
            "EnrollSelf": { "role": role }
        })
    };

    let mut msg = serde_json::to_string(&request)?;
    msg.push('\n');
    stream.write_all(msg.as_bytes())?;
    stream.flush()?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut reader = BufReader::new(&stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line)?;

    let resp: serde_json::Value = serde_json::from_str(&response_line)
        .map_err(|e| anyhow::anyhow!("invalid response: {}", e))?;

    if let Some(cgroup) = resp.get("Enrolled").and_then(|v| v.get("cgroup")).and_then(|v| v.as_str()) {
        println!("Enrolled PID {} into role \"{}\" (cgroup: {})", pid, role, cgroup);
        Ok(())
    } else if resp == serde_json::json!("Success") {
        println!("Enrolled PID {} into role \"{}\"", pid, role);
        Ok(())
    } else if let Some(err) = resp.get("Error").and_then(|v| v.as_str()) {
        bail!("enrollment failed: {}", err);
    } else {
        bail!("unexpected response: {}", response_line.trim());
    }
}
