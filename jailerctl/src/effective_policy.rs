use anyhow::Result;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

const SOCKET_PATH: &str = "/run/icb-sandbox/enrollment.sock";

pub fn run() -> Result<()> {
    let mut stream = UnixStream::connect(SOCKET_PATH)
        .map_err(|e| anyhow::anyhow!(
            "cannot connect to {}: {}. Is the daemon running?",
            SOCKET_PATH, e
        ))?;

    let request = serde_json::json!("EffectivePolicy");
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

    if let Some(err) = resp.get("Error").and_then(|v| v.as_str()) {
        anyhow::bail!("daemon error: {}", err);
    }

    let info = resp.get("EffectivePolicyInfo")
        .ok_or_else(|| anyhow::anyhow!("unexpected response"))?;

    let roles = info.get("roles")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("missing roles in response"))?;

    for role in roles {
        let name = role.get("name").and_then(|v| v.as_str()).unwrap_or("?");
        let id = role.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
        println!("Role: {} (id={})", name, id);
        println!("{}", "=".repeat(40));

        if let Some(flags) = role.get("flags").and_then(|v| v.as_array()) {
            println!("  Flags:");
            for f in flags {
                if let (Some(k), Some(v)) = (
                    f.get(0).and_then(|x| x.as_str()),
                    f.get(1).and_then(|x| x.as_bool()),
                ) {
                    println!("    {:<20} {}", k, if v { "yes" } else { "no" });
                }
            }
        }

        if let Some(paths) = role.get("file_paths").and_then(|v| v.as_array()) {
            if !paths.is_empty() {
                println!("  File paths:");
                for p in paths {
                    print_rule(p);
                }
            }
        }

        if let Some(ips) = role.get("ip_rules").and_then(|v| v.as_array()) {
            if !ips.is_empty() {
                println!("  IP rules:");
                for r in ips {
                    print_rule(r);
                }
            }
        }

        if let Some(domains) = role.get("domain_rules").and_then(|v| v.as_array()) {
            if !domains.is_empty() {
                println!("  Domain rules:");
                for r in domains {
                    print_rule(r);
                }
            }
        }

        if let Some(proxy) = role.get("proxy").and_then(|v| v.as_str()) {
            println!("  Proxy: {}", proxy);
        }

        println!();
    }

    Ok(())
}

fn print_rule(rule: &serde_json::Value) {
    let text = rule.get("rule").and_then(|v| v.as_str()).unwrap_or("?");
    let source = rule.get("source").and_then(|v| v.as_str()).unwrap_or("?");
    let lockdown = rule.get("lockdown").and_then(|v| v.as_bool()).unwrap_or(false);
    let lock_marker = if lockdown { " [LOCKED]" } else { "" };
    println!("    {:<40} ({}){}", text, source, lock_marker);
}
