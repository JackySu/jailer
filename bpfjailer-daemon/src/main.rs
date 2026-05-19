mod bpf_loader;
mod process_tracker;
mod policy;
mod enrollment;
mod enrollment_alternatives;
mod path_matcher;
mod signed_binary;

use anyhow::Result;
use log::{error, info, warn};
use std::env;
use std::path::Path;
use std::sync::Arc;
use tokio::signal;
use tokio::signal::unix::{signal as unix_signal, SignalKind};
use tokio::sync::RwLock;

const DEFAULT_POLICY_PATH: &str = "/etc/bpfjailer/policy.json";
const LOCAL_POLICY_PATH: &str = "config/policy.json";

/// Emergency disable: if this file exists, the daemon refuses to attach LSM
/// hooks (or detaches them on SIGHUP). Designed for IT to remotely push a
/// kill-switch via configuration management without needing to stop the
/// daemon process itself.
const DISABLED_SENTINEL: &str = "/etc/bpfjailer/disabled";

fn is_disabled() -> bool {
    Path::new(DISABLED_SENTINEL).exists()
}

fn log_disabled_banner() {
    warn!("================================================================");
    warn!("=  EMERGENCY DISABLE active: {} exists.", DISABLED_SENTINEL);
    warn!("=  BPF LSM programs NOT attached. NO enforcement.");
    warn!("=  Remove the sentinel and `systemctl reload bpfjailer-daemon`");
    warn!("=  (or send SIGHUP) to re-enable enforcement.");
    warn!("================================================================");
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    info!("BpfJailer daemon starting...");

    let bpf = match bpf_loader::BpfJailerBpf::load() {
        Ok(b) => Arc::new(b),
        Err(e) => {
            error!("Failed to load eBPF programs: {}", e);
            return Err(e);
        }
    };

    // Emergency-disable gate: check sentinel BEFORE attaching LSM hooks. If
    // the file is there we still start everything else (socket, policy load,
    // map population), so removing the sentinel + SIGHUP is enough to resume.
    if is_disabled() {
        log_disabled_banner();
    } else {
        bpf.attach_lsm_programs()?;
    }

    // Initialize policy manager with default roles
    let mut policy_manager = policy::PolicyManager::new()?;

    // Load policy from file if available
    let policy_path = env::var("BPFJAILER_POLICY")
        .ok()
        .or_else(|| {
            if Path::new(DEFAULT_POLICY_PATH).exists() {
                Some(DEFAULT_POLICY_PATH.to_string())
            } else if Path::new(LOCAL_POLICY_PATH).exists() {
                Some(LOCAL_POLICY_PATH.to_string())
            } else {
                None
            }
        });

    if let Some(path) = policy_path {
        match policy_manager.load_from_file(&path).await {
            Ok(()) => info!("Loaded policy from {}", path),
            Err(e) => warn!("Failed to load policy from {}: {}", path, e),
        }
    } else {
        info!("No policy file found, using default roles");
    }

    let policy_manager = Arc::new(RwLock::new(policy_manager));
    let process_tracker = Arc::new(process_tracker::ProcessTracker::new(bpf.clone())?);
    let path_matcher = Arc::new(path_matcher::PathMatcher::new(bpf.clone())?);
    let _signed_binary = Arc::new(signed_binary::SignedBinaryManager::new(bpf.clone())?);

    // Compile path patterns from loaded policy and invalidate cache
    {
        let pm = policy_manager.read().await;
        let all_patterns: Vec<String> = pm.config().roles.values()
            .flat_map(|role| role.file_paths.iter().map(|p| p.pattern.clone()))
            .collect();
        drop(pm);

        if !all_patterns.is_empty() {
            if let Err(e) = path_matcher.compile_patterns(&all_patterns) {
                warn!("Failed to compile path patterns: {}", e);
            }
            // Invalidate cache since path rules may have changed
            if let Err(e) = path_matcher.invalidate_cache() {
                warn!("Failed to invalidate cache: {}", e);
            }
        }
    }

    // Apply IP rules, domain rules, and proxy config from policy
    {
        let pm = policy_manager.read().await;
        for (_name, role) in pm.config().roles.iter() {
            let role_id = role.id;

            // Apply IP rules
            if !role.ip_rules.is_empty() {
                if let Err(e) = process_tracker.apply_ip_rules(role_id, &role.ip_rules) {
                    warn!("Failed to apply IP rules for role {}: {}", role_id.0, e);
                }
            }

            // Apply domain rules
            if !role.domain_rules.is_empty() {
                if let Err(e) = process_tracker.apply_domain_rules(role_id, &role.domain_rules) {
                    warn!("Failed to apply domain rules for role {}: {}", role_id.0, e);
                }
            }

            // Apply proxy config
            if let Some(ref proxy) = role.proxy {
                if let Err(e) = process_tracker.set_proxy_config(role_id, proxy) {
                    warn!("Failed to set proxy config for role {}: {}", role_id.0, e);
                }
            }
        }
    }

    // Initialize alternative enrollment methods
    let alt_enrollment = Arc::new(enrollment_alternatives::AlternativeEnrollment::new(
        bpf.clone(),
        process_tracker.clone(),
        policy_manager.clone(),
    ));

    // Load auto-enrollment rules from policy
    if let Err(e) = alt_enrollment.load_from_policy().await {
        warn!("Failed to load auto-enrollment rules: {}", e);
    }

    let enrollment_server = enrollment::EnrollmentServer::new(
        process_tracker.clone(),
        policy_manager.clone(),
        alt_enrollment.clone(),
        bpf.clone(),
    );

    let server_handle = tokio::spawn(async move {
        if let Err(e) = enrollment_server.run().await {
            error!("Enrollment server error: {}", e);
        }
    });

    info!("BpfJailer daemon started (enforcement {})",
          if bpf.is_attached() { "ON" } else { "OFF (disabled sentinel present)" });
    info!("SIGHUP re-evaluates the disable sentinel; Ctrl+C shuts down.");

    let mut sighup = unix_signal(SignalKind::hangup())?;

    loop {
        tokio::select! {
            _ = sighup.recv() => {
                let now_disabled = is_disabled();
                let was_attached = bpf.is_attached();
                info!("SIGHUP received (disabled={}, was_attached={})", now_disabled, was_attached);
                match (was_attached, now_disabled) {
                    (true, true) => {
                        warn!("Disable sentinel appeared, detaching LSM programs");
                        bpf.detach_lsm_programs();
                        log_disabled_banner();
                    }
                    (false, false) => {
                        info!("Disable sentinel removed, re-attaching LSM programs");
                        match bpf.attach_lsm_programs() {
                            Ok(()) => info!("Enforcement resumed"),
                            Err(e) => error!("Re-attach failed: {} (daemon still running, no enforcement)", e),
                        }
                    }
                    _ => {
                        info!("No state change required for this SIGHUP");
                    }
                }
            }
            _ = signal::ctrl_c() => {
                info!("Shutting down...");
                break;
            }
        }
    }

    server_handle.abort();

    info!("BpfJailer daemon stopped");
    Ok(())
}
