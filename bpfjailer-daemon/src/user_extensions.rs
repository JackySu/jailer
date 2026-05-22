use anyhow::Result;
use bpfjailer_common::{PathPattern, Role, UserExtensionConfig};
use log::{info, warn};
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Discover user config files by reading /etc/passwd.
/// Returns (uid, username, config_path) for each user that has a config file.
pub fn discover_user_configs() -> Vec<(u32, String, PathBuf)> {
    let passwd = match std::fs::read_to_string("/etc/passwd") {
        Ok(c) => c,
        Err(e) => {
            warn!("Cannot read /etc/passwd: {}", e);
            return Vec::new();
        }
    };

    let mut results = Vec::new();
    for line in passwd.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 6 {
            continue;
        }
        let username = fields[0];
        let uid: u32 = match fields[2].parse() {
            Ok(u) => u,
            Err(_) => continue,
        };
        let home = fields[5];

        // Skip system users (uid < 1000) and nologin shells
        if uid < 1000 {
            continue;
        }
        if let Some(shell) = fields.get(6) {
            if shell.contains("nologin") || shell.contains("/false") {
                continue;
            }
        }

        let config_path = PathBuf::from(home)
            .join(".config/icb/sandbox/policy.toml");
        if config_path.exists() {
            results.push((uid, username.to_string(), config_path));
        }
    }
    results
}

/// Load and validate a user's extension config.
/// Rejects the file if: owned by wrong uid, is a symlink, or contains invalid rules.
pub fn load_user_config(path: &Path, uid: u32) -> Result<UserExtensionConfig> {
    let meta = std::fs::symlink_metadata(path)?;

    // Reject symlinks to prevent privilege escalation
    if meta.file_type().is_symlink() {
        anyhow::bail!("rejecting symlink at {}", path.display());
    }

    // Verify file is owned by the expected user
    if meta.uid() != uid {
        anyhow::bail!(
            "{} owned by uid {} but expected {}",
            path.display(),
            meta.uid(),
            uid
        );
    }

    let content = std::fs::read_to_string(path)?;
    let config: UserExtensionConfig = toml::from_str(&content)
        .map_err(|e| anyhow::anyhow!("invalid user extension TOML: {}", e))?;
    Ok(config)
}

/// Validate user extensions against the IT policy role.
/// Returns Ok(()) if all rules are valid, or Err with list of violations.
pub fn validate_user_config(
    config: &UserExtensionConfig,
    role: &Role,
    username: &str,
) -> std::result::Result<(), Vec<String>> {
    let mut errors = Vec::new();

    for (i, ext) in config.user_extensions.iter().enumerate() {
        // Users cannot grant access
        if ext.allow {
            errors.push(format!(
                "[{}] user_extensions[{}]: allow=true is forbidden (pattern: {})",
                username, i, ext.pattern
            ));
        }

        // Users cannot set lockdown
        if ext.lockdown {
            errors.push(format!(
                "[{}] user_extensions[{}]: lockdown=true is forbidden (pattern: {})",
                username, i, ext.pattern
            ));
        }

        // Check if pattern conflicts with a lockdown'd rule in the IT policy
        for base_rule in &role.file_paths {
            if base_rule.lockdown && patterns_overlap(&ext.pattern, &base_rule.pattern) {
                errors.push(format!(
                    "[{}] user_extensions[{}]: pattern \"{}\" conflicts with lockdown rule \"{}\"",
                    username, i, ext.pattern, base_rule.pattern
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Check if two path patterns overlap (one is a prefix of the other).
fn patterns_overlap(a: &str, b: &str) -> bool {
    a.starts_with(b) || b.starts_with(a) || a == b
}

/// Load all user extensions, validate them, and return valid ones + error log.
pub fn load_all(
    roles: &HashMap<String, Role>,
) -> (HashMap<u32, Vec<PathPattern>>, Vec<String>) {
    let mut extensions: HashMap<u32, Vec<PathPattern>> = HashMap::new();
    let mut all_errors: Vec<String> = Vec::new();

    let configs = discover_user_configs();
    if configs.is_empty() {
        return (extensions, all_errors);
    }

    info!("Scanning {} user extension config(s)", configs.len());

    for (uid, username, path) in &configs {
        let config = match load_user_config(path, *uid) {
            Ok(c) => c,
            Err(e) => {
                let msg = format!("[{}] failed to load {}: {}", username, path.display(), e);
                warn!("{}", msg);
                all_errors.push(msg);
                continue;
            }
        };

        if config.user_extensions.is_empty() {
            continue;
        }

        // Validate against all roles (user extensions apply to whichever role
        // the user gets enrolled into, so validate against all)
        let mut valid = true;
        for role in roles.values() {
            if let Err(errs) = validate_user_config(&config, role, username) {
                for e in &errs {
                    warn!("{}", e);
                }
                all_errors.extend(errs);
                valid = false;
                break;
            }
        }

        if valid {
            let patterns: Vec<PathPattern> = config.user_extensions.into_iter()
                .map(|mut p| { p.lockdown = false; p.allow = false; p })
                .collect();
            info!("[{}] loaded {} user extension rule(s)", username, patterns.len());
            extensions.insert(*uid, patterns);
        }
    }

    (extensions, all_errors)
}
