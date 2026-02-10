use serde::{Deserialize, Serialize};

/// A filesystem permission entry: literal path or preset.
///
/// In TOML:
/// - `"/opt/data"` — literal path
/// - `{ preset = "system" }` — uv-defined preset
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub enum FsEntry {
    /// A literal filesystem path.
    Path(String),
    /// A uv-defined preset that expands to one or more paths.
    Preset { preset: FsPreset },
}

/// Named filesystem presets.
///
/// Some presets are intended for `allow-*` fields (like `project`, `python`, `system`),
/// while others are intended for `deny-*` fields (like `known-secrets`, `shell-configs`).
/// The type system does not enforce this distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum FsPreset {
    /// The project root directory.
    Project,
    /// Python interpreter, stdlib, and site-packages.
    Python,
    /// The project virtual environment.
    Virtualenv,
    /// Common system libraries and resources.
    System,
    /// The user's home directory.
    Home,
    /// The uv cache directory.
    UvCache,
    /// Temporary directories.
    Tmp,
    /// Credential files: `~/.ssh/`, `~/.gnupg/`, `~/.aws/`, etc.
    KnownSecrets,
    /// Shell config files: `.bashrc`, `.zshrc`, `.profile`, etc.
    ShellConfigs,
    /// Git hook and config files: `.git/hooks/`, `.git/config`, etc.
    GitHooks,
    /// IDE/editor config directories: `.vscode/`, `.idea/`.
    IdeConfigs,
}

/// An environment variable permission entry: literal name or preset.
///
/// In TOML:
/// - `"DATABASE_URL"` — literal variable name
/// - `"AWS_*"` — prefix wildcard
/// - `{ preset = "standard" }` — uv-defined preset
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub enum EnvEntry {
    /// A literal environment variable name. Supports `*` suffix wildcards.
    Name(String),
    /// A uv-defined preset that expands to a set of variable names.
    Preset { preset: EnvPreset },
}

/// Named environment variable presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum EnvPreset {
    /// Common safe variables: `PATH`, `HOME`, `LANG`, `TERM`, `VIRTUAL_ENV`, etc.
    Standard,
    /// Common secret variable patterns: `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, etc.
    KnownSecrets,
}

/// A network host permission entry: literal hostname or preset.
///
/// In TOML:
/// - `"example.com"` — literal hostname
/// - `"*.github.com"` — wildcard domain
/// - `{ preset = "pypi" }` — uv-defined preset
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub enum NetEntry {
    /// A literal hostname, optionally with port. Supports `*` prefix wildcards.
    Host(String),
    /// A uv-defined preset that expands to a set of hostnames.
    Preset { preset: NetPreset },
}

/// Named network presets (phase 2: domain-level filtering).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum NetPreset {
    /// `pypi.org`, `files.pythonhosted.org`.
    Pypi,
    /// `github.com`, `*.github.com`, `api.github.com`, etc.
    Github,
    /// `registry.npmjs.org`, `*.npmjs.org`.
    Npm,
    /// `jsr.io`, `*.jsr.io`.
    Jsr,
}

/// Network access control.
///
/// - `false` — deny all network access (default)
/// - `true` — allow all network access
/// - `["example.com", { preset = "pypi" }]` — allow specific hosts (phase 2)
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub enum AllowNet {
    /// `true` = allow all, `false` = deny all.
    Bool(bool),
    /// Allow specific hosts/presets (phase 2).
    Hosts(Vec<NetEntry>),
}

impl Default for AllowNet {
    fn default() -> Self {
        Self::Bool(false)
    }
}

/// Environment variable access control.
///
/// - `false` — pass no environment variables (default)
/// - `true` — pass all environment variables
/// - `[{ preset = "standard" }, "DATABASE_URL"]` — pass specific variables/presets
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub enum AllowEnv {
    /// `true` = pass all, `false` = pass none.
    Bool(bool),
    /// Pass specific variables/presets.
    List(Vec<EnvEntry>),
}

impl Default for AllowEnv {
    fn default() -> Self {
        Self::Bool(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_fs_entry_path() {
        let entry: FsEntry = serde_json::from_str(r#""/opt/data""#).unwrap();
        assert_eq!(entry, FsEntry::Path("/opt/data".to_string()));
    }

    #[test]
    fn deserialize_fs_entry_preset() {
        let entry: FsEntry = serde_json::from_str(r#"{"preset": "system"}"#).unwrap();
        assert_eq!(
            entry,
            FsEntry::Preset {
                preset: FsPreset::System
            }
        );
    }

    #[test]
    fn deserialize_fs_entry_preset_kebab_case() {
        let entry: FsEntry = serde_json::from_str(r#"{"preset": "known-secrets"}"#).unwrap();
        assert_eq!(
            entry,
            FsEntry::Preset {
                preset: FsPreset::KnownSecrets
            }
        );
    }

    #[test]
    fn deserialize_env_entry_name() {
        let entry: EnvEntry = serde_json::from_str(r#""DATABASE_URL""#).unwrap();
        assert_eq!(entry, EnvEntry::Name("DATABASE_URL".to_string()));
    }

    #[test]
    fn deserialize_env_entry_preset() {
        let entry: EnvEntry = serde_json::from_str(r#"{"preset": "standard"}"#).unwrap();
        assert_eq!(
            entry,
            EnvEntry::Preset {
                preset: EnvPreset::Standard
            }
        );
    }

    #[test]
    fn deserialize_allow_net_bool() {
        let net: AllowNet = serde_json::from_str("false").unwrap();
        assert!(matches!(net, AllowNet::Bool(false)));

        let net: AllowNet = serde_json::from_str("true").unwrap();
        assert!(matches!(net, AllowNet::Bool(true)));
    }

    #[test]
    fn deserialize_allow_net_hosts() {
        let net: AllowNet = serde_json::from_str(r#"["example.com", {"preset": "pypi"}]"#).unwrap();
        if let AllowNet::Hosts(hosts) = net {
            assert_eq!(hosts.len(), 2);
            assert_eq!(hosts[0], NetEntry::Host("example.com".to_string()));
            assert_eq!(
                hosts[1],
                NetEntry::Preset {
                    preset: NetPreset::Pypi
                }
            );
        } else {
            panic!("expected Hosts variant");
        }
    }

    #[test]
    fn deserialize_allow_env_bool() {
        let env: AllowEnv = serde_json::from_str("true").unwrap();
        assert!(matches!(env, AllowEnv::Bool(true)));
    }

    #[test]
    fn deserialize_allow_env_list() {
        let env: AllowEnv =
            serde_json::from_str(r#"[{"preset": "standard"}, "DATABASE_URL"]"#).unwrap();
        if let AllowEnv::List(entries) = env {
            assert_eq!(entries.len(), 2);
            assert_eq!(
                entries[0],
                EnvEntry::Preset {
                    preset: EnvPreset::Standard
                }
            );
            assert_eq!(entries[1], EnvEntry::Name("DATABASE_URL".to_string()));
        } else {
            panic!("expected List variant");
        }
    }

    #[test]
    fn deserialize_fs_preset_invalid() {
        let result: Result<FsEntry, _> =
            serde_json::from_str(r#"{"preset": "nonexistent-preset"}"#);
        assert!(result.is_err());
    }
}
