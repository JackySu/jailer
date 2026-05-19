use anyhow::Result;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

const SOCKET_PATH: &str = "/run/bpfjailer/enrollment.sock";

pub fn run() -> Result<()> {
    let mut stream = UnixStream::connect(SOCKET_PATH).map_err(|e| {
        anyhow::anyhow!(
            "cannot connect to {}: {}. Is the daemon running?",
            SOCKET_PATH,
            e
        )
    })?;

    let request = serde_json::json!("Status");
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

    if let Some(info) = resp.get("StatusInfo") {
        let attached = info.get("attached").and_then(|v| v.as_bool()).unwrap_or(false);
        let hooks = info.get("lsm_hooks").and_then(|v| v.as_u64()).unwrap_or(0);
        let roles = info.get("roles").and_then(|v| v.as_array());
        let cgroup_e = info.get("cgroup_enrollments").and_then(|v| v.as_u64()).unwrap_or(0);
        let exec_e = info.get("exec_enrollments").and_then(|v| v.as_u64()).unwrap_or(0);
        let policy = info.get("policy_path").and_then(|v| v.as_str()).unwrap_or("?");

        let status_icon = if attached { "\x1b[32m●\x1b[0m" } else { "\x1b[31m○\x1b[0m" };
        let status_text = if attached { "enforcing" } else { "disabled" };

        println!("{} bpfjailer-daemon: {}", status_icon, status_text);
        println!("  LSM hooks:    {}", hooks);
        println!("  Policy:       {}", policy);
        if let Some(role_list) = roles {
            let names: Vec<&str> = role_list.iter().filter_map(|v| v.as_str()).collect();
            println!("  Roles:        {} ({})", names.len(), names.join(", "));
        }
        println!("  Enrollments:  {} cgroup, {} exec", cgroup_e, exec_e);
    } else if let Some(err) = resp.get("Error").and_then(|v| v.as_str()) {
        anyhow::bail!("status query failed: {}", err);
    } else {
        println!("{}", response_line.trim());
    }
    Ok(())
}
