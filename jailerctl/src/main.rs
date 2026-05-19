mod doctor;
mod run;
mod status;
mod enroll;
mod audit;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "jailerctl", about = "CLI for managing bpfjailer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check system readiness for bpfjailer
    Doctor,
    /// Run a command inside the jailer sandbox
    Run {
        /// Policy file to use (default: /etc/bpfjailer/policy.json)
        #[arg(long, short)]
        policy: Option<String>,
        /// Cgroup path to join (default: /sys/fs/cgroup/bpfjailer/code-agent)
        #[arg(long)]
        cgroup: Option<String>,
        /// Command to run (default: bash --login)
        #[arg(trailing_var_arg = true)]
        cmd: Vec<String>,
    },
    /// Send SIGHUP to the daemon (re-evaluate disable sentinel)
    Reload,
    /// Validate a policy JSON file without loading it
    Validate {
        /// Path to the policy file
        path: String,
    },
    /// Show daemon status (attached state, loaded policy summary)
    Status,
    /// Enroll a process into a jailer role
    Enroll {
        /// Role name to assign
        #[arg(long, short, default_value = "code_agent")]
        role: String,
        /// PID to enroll (default: self)
        #[arg(long)]
        pid: Option<u32>,
    },
    /// Show recent audit events from BPF LSM denials
    Audit {
        /// Only show events for the current user
        #[arg(long)]
        me: bool,
        /// Time range (journalctl --since format, default: "5min ago")
        #[arg(long)]
        since: Option<String>,
        /// Filter by role name
        #[arg(long)]
        role: Option<String>,
        /// Follow new events in real time
        #[arg(long, short)]
        follow: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Doctor => doctor::run(),
        Commands::Run { policy, cgroup, cmd } => run::run(policy, cgroup, cmd),
        Commands::Reload => reload(),
        Commands::Validate { path } => validate(&path),
        Commands::Status => status::run(),
        Commands::Enroll { role, pid } => {
            enroll::run(pid.unwrap_or(std::process::id()), &role)
        }
        Commands::Audit { me, since, role, follow } => {
            audit::run(me, since.as_deref(), role.as_deref(), follow)
        }
    }
}

fn reload() -> Result<()> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let socket_path = "/run/bpfjailer/enrollment.sock";
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| anyhow::anyhow!(
            "cannot connect to {}: {}. Is the daemon running? Are you in the 'bpfjailer' group?",
            socket_path, e
        ))?;

    let request = serde_json::json!("Reload");
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

    if resp == serde_json::json!("Success") {
        println!("Reload signal sent. Daemon will re-read policy and user extensions.");
    } else if let Some(err) = resp.get("Error").and_then(|v| v.as_str()) {
        anyhow::bail!("reload failed: {}", err);
    } else {
        println!("Response: {}", response_line.trim());
    }
    Ok(())
}

fn validate(path: &str) -> Result<()> {
    use std::fs;

    let content = fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {}", path, e))?;

    let value: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("invalid JSON in {}: {}", path, e))?;

    // Basic structural checks
    let mut errors: Vec<String> = Vec::new();

    if let Some(roles) = value.get("roles").and_then(|v| v.as_object()) {
        for (name, role) in roles {
            if role.get("id").and_then(|v| v.as_u64()).is_none() {
                errors.push(format!("role \"{}\": missing or invalid 'id' field", name));
            }
            if let Some(paths) = role.get("file_paths").and_then(|v| v.as_array()) {
                for (i, p) in paths.iter().enumerate() {
                    let pattern = p.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
                    if pattern.starts_with('~') {
                        errors.push(format!(
                            "role \"{}\".file_paths[{}]: pattern \"{}\" uses ~ shorthand. \
                             Use absolute paths (/home/*/...) instead.",
                            name, i, pattern
                        ));
                    }
                    if !pattern.starts_with('/') && !pattern.starts_with('~') {
                        errors.push(format!(
                            "role \"{}\".file_paths[{}]: pattern \"{}\" is not an absolute path",
                            name, i, pattern
                        ));
                    }
                    if p.get("allow").is_none() {
                        errors.push(format!(
                            "role \"{}\".file_paths[{}]: missing 'allow' field",
                            name, i
                        ));
                    }
                }
            }
        }
    } else {
        errors.push("missing top-level 'roles' object".to_string());
    }

    if errors.is_empty() {
        println!("\x1b[32m✓\x1b[0m {} is valid", path);
        Ok(())
    } else {
        eprintln!("\x1b[31m✗\x1b[0m {} has {} error(s):\n", path, errors.len());
        for e in &errors {
            eprintln!("  - {}", e);
        }
        anyhow::bail!("validation failed");
    }
}
