use anyhow::{Context, Result};
use bpfjailer_client::{EnrollmentRequest, EnrollmentResponse};
use log::{debug, error, info, warn};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener as AsyncUnixListener, UnixStream as AsyncUnixStream};
use tokio::sync::RwLock;
use crate::bpf_loader::BpfJailerBpf;
use crate::process_tracker::ProcessTracker;
use crate::policy::PolicyManager;
use crate::enrollment_alternatives::AlternativeEnrollment;

const SOCKET_PATH: &str = "/run/bpfjailer/enrollment.sock";
const CGROUP_BASE: &str = "/sys/fs/cgroup/bpfjailer";
const BPFJAILER_GROUP: &str = "bpfjailer";

pub struct EnrollmentServer {
    process_tracker: Arc<ProcessTracker>,
    policy_manager: Arc<RwLock<PolicyManager>>,
    alt_enrollment: Arc<AlternativeEnrollment>,
    bpf: Arc<BpfJailerBpf>,
}

impl EnrollmentServer {
    pub fn new(
        process_tracker: Arc<ProcessTracker>,
        policy_manager: Arc<RwLock<PolicyManager>>,
        alt_enrollment: Arc<AlternativeEnrollment>,
        bpf: Arc<BpfJailerBpf>,
    ) -> Self {
        Self {
            process_tracker,
            policy_manager,
            alt_enrollment,
            bpf,
        }
    }

    pub async fn run(&self) -> Result<()> {
        if Path::new(SOCKET_PATH).exists() {
            std::fs::remove_file(SOCKET_PATH)?;
        }

        if let Some(parent) = Path::new(SOCKET_PATH).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = AsyncUnixListener::bind(SOCKET_PATH)
            .context("Failed to bind enrollment socket")?;

        // Set socket permissions to root:bpfjailer 0660 so unprivileged users
        // in the bpfjailer group can connect without sudo.
        Self::set_socket_permissions()?;

        info!("Enrollment server listening on {}", SOCKET_PATH);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let process_tracker = self.process_tracker.clone();
                    let policy_manager = self.policy_manager.clone();
                    let alt_enrollment = self.alt_enrollment.clone();
                    let bpf = self.bpf.clone();

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_client(stream, process_tracker, policy_manager, alt_enrollment, bpf).await {
                            error!("Error handling enrollment client: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                }
            }
        }
    }

    fn set_socket_permissions() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        // Try to look up the bpfjailer group. If it doesn't exist, fall back
        // to mode 0666 (world-accessible) with a warning.
        let gid = Self::lookup_group_gid(BPFJAILER_GROUP);
        match gid {
            Some(_) => {
                let status = std::process::Command::new("chgrp")
                    .args([BPFJAILER_GROUP, SOCKET_PATH])
                    .status();
                if status.map(|s| s.success()).unwrap_or(false) {
                    std::fs::set_permissions(
                        SOCKET_PATH,
                        std::fs::Permissions::from_mode(0o660),
                    )?;
                    info!("Socket permissions set to root:{} 0660", BPFJAILER_GROUP);
                } else {
                    warn!("chgrp failed, falling back to 0666");
                    std::fs::set_permissions(
                        SOCKET_PATH,
                        std::fs::Permissions::from_mode(0o666),
                    )?;
                }
            }
            None => {
                warn!(
                    "Group '{}' not found. Socket set to 0666 (any user can connect). \
                     Create the group for production use: groupadd {}",
                    BPFJAILER_GROUP, BPFJAILER_GROUP
                );
                std::fs::set_permissions(
                    SOCKET_PATH,
                    std::fs::Permissions::from_mode(0o666),
                )?;
            }
        }
        Ok(())
    }

    fn lookup_group_gid(name: &str) -> Option<u32> {
        let content = std::fs::read_to_string("/etc/group").ok()?;
        for line in content.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 3 && fields[0] == name {
                return fields[2].parse().ok();
            }
        }
        None
    }

    async fn handle_client(
        mut stream: AsyncUnixStream,
        process_tracker: Arc<ProcessTracker>,
        policy_manager: Arc<RwLock<PolicyManager>>,
        alt_enrollment: Arc<AlternativeEnrollment>,
        bpf: Arc<BpfJailerBpf>,
    ) -> Result<()> {
        let peer_creds = stream.peer_cred()
            .context("Failed to get peer credentials")?;

        let pid = peer_creds.pid().unwrap_or(0);
        let uid = peer_creds.uid();
        debug!("Handling enrollment request from PID {} uid {}", pid, uid);

        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        reader.read_line(&mut line).await?;

        let request: EnrollmentRequest = serde_json::from_str(&line)
            .context("Failed to parse enrollment request")?;

        let response = match request {
            EnrollmentRequest::EnrollSelf { role } => {
                Self::handle_enroll_self(pid, uid, &role, &process_tracker, &policy_manager).await
            }
            EnrollmentRequest::Reload => {
                Self::handle_reload(&bpf)
            }
            EnrollmentRequest::Status => {
                Self::handle_status(&bpf, &policy_manager).await
            }
            EnrollmentRequest::Enroll { pod_id, role_id } => {
                debug!("Enrollment request: PID {} -> Pod {} Role {}", pid, pod_id.0, role_id.0);

                let pm = policy_manager.read().await;
                match pm.get_role(role_id) {
                    None => EnrollmentResponse::Error(format!("Unknown role ID: {}", role_id.0)),
                    Some(role) => {
                        let role = role.clone();
                        drop(pm); // Release the lock

                        // Set the role policy flags in BPF
                        if let Err(e) = process_tracker.set_role_policy(role_id, &role.flags) {
                            EnrollmentResponse::Error(format!("Failed to set role policy: {}", e))
                        } else {
                            // Apply network rules from the role
                            if let Err(e) = process_tracker.apply_network_rules(role_id, &role.network_rules) {
                                error!("Failed to apply network rules: {}", e);
                            }

                            // Apply path rules from the role
                            if let Err(e) = process_tracker.apply_path_rules(role_id, &role.file_paths) {
                                error!("Failed to apply path rules: {}", e);
                            }

                            match process_tracker.enroll_process(pid as u32, pod_id, role_id) {
                                Ok(()) => EnrollmentResponse::Success,
                                Err(e) => EnrollmentResponse::Error(format!("Enrollment failed: {}", e)),
                            }
                        }
                    }
                }
            }
            EnrollmentRequest::Query { pid: query_pid } => {
                debug!("Query request for PID {}", query_pid);
                match process_tracker.get_process_info(query_pid) {
                    Ok(Some((pod_id, role_id))) => {
                        EnrollmentResponse::ProcessInfo { pod_id, role_id }
                    }
                    Ok(None) => {
                        EnrollmentResponse::Error("Process not found or not enrolled".to_string())
                    }
                    Err(e) => {
                        EnrollmentResponse::Error(format!("Query failed: {}", e))
                    }
                }
            }
            EnrollmentRequest::EnrollExecutable { executable_path, pod_id, role_id } => {
                debug!("Enroll executable request: {} -> Pod {} Role {}", executable_path, pod_id.0, role_id.0);
                match alt_enrollment.enroll_by_executable_path(&executable_path, pod_id, role_id).await {
                    Ok(()) => EnrollmentResponse::Success,
                    Err(e) => EnrollmentResponse::Error(format!("Failed to enroll executable: {}", e)),
                }
            }
            EnrollmentRequest::RemoveExecutable { executable_path } => {
                debug!("Remove executable enrollment: {}", executable_path);
                match alt_enrollment.remove_executable_enrollment(&executable_path).await {
                    Ok(()) => EnrollmentResponse::Success,
                    Err(e) => EnrollmentResponse::Error(format!("Failed to remove executable enrollment: {}", e)),
                }
            }
            EnrollmentRequest::EnrollCgroup { cgroup_path, pod_id, role_id } => {
                debug!("Enroll cgroup request: {} -> Pod {} Role {}", cgroup_path, pod_id.0, role_id.0);
                match alt_enrollment.enroll_by_cgroup_path(&cgroup_path, pod_id, role_id).await {
                    Ok(()) => EnrollmentResponse::Success,
                    Err(e) => EnrollmentResponse::Error(format!("Failed to enroll cgroup: {}", e)),
                }
            }
            EnrollmentRequest::RemoveCgroup { cgroup_path } => {
                debug!("Remove cgroup enrollment: {}", cgroup_path);
                match alt_enrollment.remove_cgroup_enrollment(&cgroup_path).await {
                    Ok(()) => EnrollmentResponse::Success,
                    Err(e) => EnrollmentResponse::Error(format!("Failed to remove cgroup enrollment: {}", e)),
                }
            }
            EnrollmentRequest::SetXattr { executable_path, pod_id, role_id } => {
                debug!("Set xattr enrollment: {} -> Pod {} Role {}", executable_path, pod_id.0, role_id.0);
                match alt_enrollment.set_xattr_enrollment(&executable_path, pod_id, role_id).await {
                    Ok(()) => EnrollmentResponse::Success,
                    Err(e) => EnrollmentResponse::Error(format!("Failed to set xattr enrollment: {}", e)),
                }
            }
            EnrollmentRequest::CheckXattr { executable_path } => {
                debug!("Check xattr enrollment: {}", executable_path);
                match alt_enrollment.check_xattr_enrollment(&executable_path).await {
                    Ok(Some((pod_id, role_id))) => EnrollmentResponse::XattrInfo { pod_id, role_id },
                    Ok(None) => EnrollmentResponse::Error("No xattr enrollment found".to_string()),
                    Err(e) => EnrollmentResponse::Error(format!("Failed to check xattr enrollment: {}", e)),
                }
            }
            EnrollmentRequest::RemoveXattr { executable_path } => {
                debug!("Remove xattr enrollment: {}", executable_path);
                match alt_enrollment.remove_xattr_enrollment(&executable_path).await {
                    Ok(()) => EnrollmentResponse::Success,
                    Err(e) => EnrollmentResponse::Error(format!("Failed to remove xattr enrollment: {}", e)),
                }
            }
        };

        let response_json = serde_json::to_string(&response)?;
        stream.write_all(response_json.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;

        Ok(())
    }

    /// Handle EnrollSelf: daemon writes caller's PID into the jailer cgroup.
    async fn handle_enroll_self(
        pid: i32,
        uid: u32,
        role_name: &str,
        process_tracker: &Arc<ProcessTracker>,
        policy_manager: &Arc<RwLock<PolicyManager>>,
    ) -> EnrollmentResponse {
        if pid <= 0 {
            return EnrollmentResponse::Error("cannot determine caller PID".into());
        }

        let pm = policy_manager.read().await;
        let role_arc = match pm.get_role_by_name(role_name) {
            Some(r) => r.clone(),
            None => {
                return EnrollmentResponse::Error(format!("unknown role: {}", role_name));
            }
        };
        let user_ext_paths = pm.effective_file_paths(role_arc.id, Some(uid));
        drop(pm);

        let role_id = role_arc.id;
        let pod_id = bpfjailer_common::PodId(pid as u64 + 10000);

        // Create the cgroup directory if it doesn't exist
        let cgroup_dir = format!("{}/{}", CGROUP_BASE, role_name);
        if !Path::new(&cgroup_dir).is_dir() {
            if let Err(e) = std::fs::create_dir_all(&cgroup_dir) {
                return EnrollmentResponse::Error(format!("mkdir {}: {}", cgroup_dir, e));
            }
        }

        // Write caller PID into cgroup.procs
        let procs_path = format!("{}/cgroup.procs", cgroup_dir);
        if let Err(e) = std::fs::write(&procs_path, format!("{}\n", pid)) {
            return EnrollmentResponse::Error(format!(
                "write {} to {}: {}", pid, procs_path, e
            ));
        }

        info!("EnrollSelf: PID {} uid {} -> cgroup {} role {}", pid, uid, cgroup_dir, role_name);

        // Set role policy and apply rules
        if let Err(e) = process_tracker.set_role_policy(role_id, &role_arc.flags) {
            return EnrollmentResponse::Error(format!("set_role_policy: {}", e));
        }
        if let Err(e) = process_tracker.apply_network_rules(role_id, &role_arc.network_rules) {
            error!("Failed to apply network rules for EnrollSelf: {}", e);
        }
        // Apply effective file_paths (base + user extensions)
        if let Err(e) = process_tracker.apply_path_rules(role_id, &user_ext_paths) {
            error!("Failed to apply path rules for EnrollSelf: {}", e);
        }

        match process_tracker.enroll_process(pid as u32, pod_id, role_id) {
            Ok(()) => EnrollmentResponse::Enrolled {
                cgroup: format!("/bpfjailer/{}", role_name),
            },
            Err(e) => EnrollmentResponse::Error(format!("enroll_process: {}", e)),
        }
    }

    /// Handle Reload: send SIGHUP to self to trigger full policy hot-reload.
    fn handle_reload(_bpf: &Arc<BpfJailerBpf>) -> EnrollmentResponse {
        info!("Reload requested via socket, raising SIGHUP");
        unsafe {
            libc::kill(libc::getpid(), libc::SIGHUP);
        }
        EnrollmentResponse::Success
    }

    /// Handle Status: report daemon state summary.
    async fn handle_status(
        bpf: &Arc<BpfJailerBpf>,
        policy_manager: &Arc<RwLock<PolicyManager>>,
    ) -> EnrollmentResponse {
        let attached = bpf.is_attached();
        let lsm_hooks = bpf.attached_count();
        let pm = policy_manager.read().await;
        let roles: Vec<String> = pm.role_names();
        let cgroup_enrollments = pm.cgroup_enrollment_count();
        let exec_enrollments = pm.exec_enrollment_count();
        let policy_path = pm.policy_path().to_string();
        drop(pm);

        EnrollmentResponse::StatusInfo {
            attached,
            lsm_hooks,
            roles,
            cgroup_enrollments,
            exec_enrollments,
            policy_path,
        }
    }
}
