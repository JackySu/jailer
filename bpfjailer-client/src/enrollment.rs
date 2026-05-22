use anyhow::{Context, Result};
use bpfjailer_common::{PodId, RoleId};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream as AsyncUnixStream;

#[derive(Debug, Serialize, Deserialize)]
pub enum EnrollmentRequest {
    Enroll {
        pod_id: PodId,
        role_id: RoleId,
    },
    Query {
        pid: u32,
    },
    /// Ask the daemon to place the calling process into the jailer cgroup and
    /// enroll it with the specified role. The daemon verifies the caller owns
    /// the PID (via SO_PEERCRED) and does the privileged cgroup write itself.
    /// This lets unprivileged users in the `bpfjailer` group use jailerctl
    /// without sudo.
    EnrollSelf {
        role: String,
    },
    /// Ask the daemon to re-evaluate the disable sentinel (equivalent to
    /// sending SIGHUP). Allows unprivileged users to trigger reload via socket
    /// instead of needing kill permissions on the daemon process.
    Reload,
    /// Query daemon status: attached state, loaded policy summary.
    Status,
    // Alternative enrollment management
    EnrollExecutable {
        executable_path: String,
        pod_id: PodId,
        role_id: RoleId,
    },
    RemoveExecutable {
        executable_path: String,
    },
    EnrollCgroup {
        cgroup_path: String,
        pod_id: PodId,
        role_id: RoleId,
    },
    RemoveCgroup {
        cgroup_path: String,
    },
    SetXattr {
        executable_path: String,
        pod_id: PodId,
        role_id: RoleId,
    },
    CheckXattr {
        executable_path: String,
    },
    RemoveXattr {
        executable_path: String,
    },
    /// Query effective policy for the calling user (merged base + drop-in + user extensions).
    EffectivePolicy,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum EnrollmentResponse {
    Success,
    Error(String),
    ProcessInfo {
        pod_id: PodId,
        role_id: RoleId,
    },
    XattrInfo {
        pod_id: PodId,
        role_id: RoleId,
    },
    /// Response to EnrollSelf — tells the caller which cgroup it was placed in.
    Enrolled {
        cgroup: String,
    },
    /// Response to Status — daemon state summary.
    StatusInfo {
        attached: bool,
        lsm_hooks: usize,
        roles: Vec<String>,
        cgroup_enrollments: usize,
        exec_enrollments: usize,
        policy_path: String,
    },
    /// Response to EffectivePolicy — merged rules with source annotations.
    EffectivePolicyInfo {
        roles: Vec<EffectiveRole>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EffectiveRole {
    pub name: String,
    pub id: u32,
    pub flags: Vec<(String, bool)>,
    pub file_paths: Vec<AnnotatedRule>,
    pub ip_rules: Vec<AnnotatedRule>,
    pub domain_rules: Vec<AnnotatedRule>,
    pub proxy: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnnotatedRule {
    pub rule: String,
    pub source: String,
    pub lockdown: bool,
}

pub struct EnrollmentClient {
    socket_path: String,
}

impl EnrollmentClient {
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub async fn enroll(&self, pod_id: PodId, role_id: RoleId) -> Result<()> {
        let mut stream = AsyncUnixStream::connect(&self.socket_path)
            .await
            .context("Failed to connect to enrollment socket")?;

        let request = EnrollmentRequest::Enroll { pod_id, role_id };
        let request_json = serde_json::to_string(&request)?;

        stream.write_all(request_json.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;

        let mut response_buf = Vec::new();
        stream.read_to_end(&mut response_buf).await?;

        let response: EnrollmentResponse = serde_json::from_slice(&response_buf)
            .context("Failed to parse enrollment response")?;

        match response {
            EnrollmentResponse::Success => Ok(()),
            EnrollmentResponse::Error(e) => Err(anyhow::anyhow!("Enrollment failed: {}", e)),
            _ => Err(anyhow::anyhow!("Unexpected response type")),
        }
    }

    pub async fn query(&self, pid: u32) -> Result<(PodId, RoleId)> {
        let mut stream = AsyncUnixStream::connect(&self.socket_path)
            .await
            .context("Failed to connect to enrollment socket")?;

        let request = EnrollmentRequest::Query { pid };
        let request_json = serde_json::to_string(&request)?;

        stream.write_all(request_json.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;

        let mut response_buf = Vec::new();
        stream.read_to_end(&mut response_buf).await?;

        let response: EnrollmentResponse = serde_json::from_slice(&response_buf)
            .context("Failed to parse query response")?;

        match response {
            EnrollmentResponse::ProcessInfo { pod_id, role_id } => Ok((pod_id, role_id)),
            EnrollmentResponse::Error(e) => Err(anyhow::anyhow!("Query failed: {}", e)),
            _ => Err(anyhow::anyhow!("Unexpected response type")),
        }
    }
}
