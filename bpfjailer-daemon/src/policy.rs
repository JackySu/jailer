use anyhow::Result;
use bpfjailer_common::{PathPattern, PolicyConfig, PolicyFlags, PodId, Role, RoleId};
use log::info;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::fs;

use crate::user_extensions;

const DROP_IN_DIR: &str = "/etc/icb/sandbox/policy.d";

pub struct PolicyManager {
    config: PolicyConfig,
    role_map: HashMap<RoleId, Arc<Role>>,
    loaded_path: String,
    extensions: HashMap<u32, Vec<PathPattern>>,
}

impl PolicyManager {
    pub fn new() -> Result<Self> {
        let mut config = PolicyConfig::new();
        let mut role_map = HashMap::new();

        // Add default test roles
        // Role 1: Restricted - blocks file, network, exec
        let restricted_role = Role {
            id: RoleId(1),
            name: "restricted".to_string(),
            flags: PolicyFlags {
                allow_file_access: false,
                allow_network: false,
                allow_exec: false,
                require_signed_binary: false,
                allow_setuid: false,
                allow_ptrace: false,
                allow_module_load: false,
                allow_bpf_load: false,
                require_proxy: false,
            },
            file_paths: vec![],
            network_rules: vec![],
            execution_rules: vec![],
            require_signed_binary: false,
            ip_rules: vec![],
            domain_rules: vec![],
            proxy: None,
        };

        // Role 2: Permissive - allows everything
        let permissive_role = Role {
            id: RoleId(2),
            name: "permissive".to_string(),
            flags: PolicyFlags {
                allow_file_access: true,
                allow_network: true,
                allow_exec: true,
                require_signed_binary: false,
                allow_setuid: false,
                allow_ptrace: false,
                allow_module_load: true,
                allow_bpf_load: true,
                require_proxy: false,
            },
            file_paths: vec![],
            network_rules: vec![],
            execution_rules: vec![],
            require_signed_binary: false,
            ip_rules: vec![],
            domain_rules: vec![],
            proxy: None,
        };

        config.roles.insert("restricted".to_string(), restricted_role.clone());
        config.roles.insert("permissive".to_string(), permissive_role.clone());
        role_map.insert(RoleId(1), Arc::new(restricted_role));
        role_map.insert(RoleId(2), Arc::new(permissive_role));

        info!("Initialized with default roles: restricted (1), permissive (2)");

        Ok(Self {
            config,
            role_map,
            loaded_path: "(defaults)".to_string(),
            extensions: HashMap::new(),
        })
    }

    pub async fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path_ref = path.as_ref();
        info!("Loading policy from {:?}", path_ref);
        self.loaded_path = path_ref.display().to_string();
        let content = fs::read_to_string(path_ref).await?;
        self.config = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("policy parse error: {}", e))?;

        // Merge drop-in fragments from /etc/icb/sandbox/policy.d/*.toml
        self.load_drop_ins().await;

        self.role_map.clear();
        for (_name, role) in &self.config.roles {
            self.role_map.insert(role.id, Arc::new(role.clone()));
        }

        info!("Loaded {} roles", self.role_map.len());
        Ok(())
    }

    /// Load drop-in policy fragments from /etc/icb/sandbox/policy.d/*.toml
    /// Merged in alphabetical order; later files override earlier ones.
    async fn load_drop_ins(&mut self) {
        let dir = Path::new(DROP_IN_DIR);
        if !dir.is_dir() {
            return;
        }

        let mut entries: Vec<std::path::PathBuf> = match std::fs::read_dir(dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().map(|e| e == "toml").unwrap_or(false))
                .collect(),
            Err(e) => {
                log::warn!("Cannot read {}: {}", DROP_IN_DIR, e);
                return;
            }
        };
        entries.sort();

        for path in &entries {
            match fs::read_to_string(path).await {
                Ok(content) => match toml::from_str::<PolicyConfig>(&content) {
                    Ok(fragment) => {
                        let count = fragment.roles.len();
                        for (name, role) in fragment.roles {
                            self.config.roles.insert(name, role);
                        }
                        self.config.exec_enrollments.extend(fragment.exec_enrollments);
                        self.config.cgroup_enrollments.extend(fragment.cgroup_enrollments);
                        self.config.pods.extend(fragment.pods);
                        info!("Merged drop-in {:?} ({} roles)", path.file_name().unwrap_or_default(), count);
                    }
                    Err(e) => log::warn!("Invalid TOML in {:?}: {}", path, e),
                },
                Err(e) => log::warn!("Cannot read {:?}: {}", path, e),
            }
        }
    }

    pub fn get_role(&self, role_id: RoleId) -> Option<&Arc<Role>> {
        self.role_map.get(&role_id)
    }

    #[allow(dead_code)]
    pub fn get_role_by_name(&self, name: &str) -> Option<&Arc<Role>> {
        self.config.get_role(name).map(|r| {
            self.role_map.get(&r.id).unwrap()
        })
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    /// Get executable enrollments from policy
    pub fn get_exec_enrollments(&self) -> Vec<(String, PodId, RoleId)> {
        self.config.exec_enrollments.iter()
            .filter_map(|e| {
                self.config.get_role(&e.role)
                    .map(|r| (e.executable_path.clone(), PodId(e.pod_id), r.id))
            })
            .collect()
    }

    /// Get cgroup enrollments from policy
    pub fn get_cgroup_enrollments(&self) -> Vec<(String, PodId, RoleId)> {
        self.config.cgroup_enrollments.iter()
            .filter_map(|e| {
                self.config.get_role(&e.role)
                    .map(|r| (e.cgroup_path.clone(), PodId(e.pod_id), r.id))
            })
            .collect()
    }

    pub fn role_names(&self) -> Vec<String> {
        self.config.roles.keys().cloned().collect()
    }

    pub fn cgroup_enrollment_count(&self) -> usize {
        self.config.cgroup_enrollments.len()
    }

    pub fn exec_enrollment_count(&self) -> usize {
        self.config.exec_enrollments.len()
    }

    pub fn policy_path(&self) -> &str {
        &self.loaded_path
    }

    /// Load user extensions from ~/.config/icb/sandbox/policy.toml for all users.
    /// Returns error messages for configs that failed validation.
    pub fn load_user_extensions(&mut self) -> Vec<String> {
        let (exts, errors) = user_extensions::load_all(&self.config.roles);
        let count = exts.len();
        self.extensions = exts;
        if count > 0 {
            info!("Loaded user extensions for {} user(s)", count);
        }
        errors
    }

    /// Get effective file_paths for a role, including user extensions if uid is provided.
    pub fn effective_file_paths(&self, role_id: RoleId, uid: Option<u32>) -> Vec<PathPattern> {
        let mut paths = match self.role_map.get(&role_id) {
            Some(role) => role.file_paths.clone(),
            None => return Vec::new(),
        };
        if let Some(uid) = uid {
            if let Some(user_exts) = self.extensions.get(&uid) {
                paths.extend(user_exts.iter().cloned());
            }
        }
        paths
    }

    /// Get user extensions for a specific uid.
    #[allow(dead_code)]
    pub fn get_user_extensions(&self, uid: u32) -> Option<&Vec<PathPattern>> {
        self.extensions.get(&uid)
    }

    pub fn extensions_count(&self) -> usize {
        self.extensions.len()
    }

    pub fn all_extensions(&self) -> &HashMap<u32, Vec<PathPattern>> {
        &self.extensions
    }

    /// Get effective file_paths for a role, merging ALL user extensions (all uids).
    pub fn effective_file_paths_all(&self, role_id: RoleId) -> Vec<PathPattern> {
        let mut paths = match self.role_map.get(&role_id) {
            Some(role) => role.file_paths.clone(),
            None => return Vec::new(),
        };
        for exts in self.extensions.values() {
            paths.extend(exts.iter().cloned());
        }
        paths
    }
}
