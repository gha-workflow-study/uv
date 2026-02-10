use serde::{Deserialize, Serialize};
use uv_macros::OptionsMetadata;

use crate::{AllowEnv, AllowNet, EnvEntry, FsEntry, NetEntry};

/// The `[tool.uv.sandbox]` / `[sandbox]` configuration.
///
/// When this section is present and the `sandbox` preview feature is enabled,
/// `uv run` will execute the command in a sandboxed environment that denies
/// all access except what is explicitly permitted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, OptionsMetadata)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct SandboxOptions {
    /// Filesystem paths the sandboxed process can read.
    ///
    /// Each entry is either a literal path (string) or a uv-defined preset (object).
    ///
    /// Presets: `project`, `python`, `virtualenv`, `system`, `home`, `uv-cache`, `tmp`.
    #[option(
        default = "[]",
        value_type = r#"list[str | { preset = "..." }]"#,
        example = r#"
            allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        "#
    )]
    pub allow_read: Option<Vec<FsEntry>>,

    /// Filesystem paths to deny reading, even within allowed paths.
    ///
    /// Deny entries take precedence over allow entries.
    ///
    /// Presets: `known-secrets`.
    #[option(
        default = "[]",
        value_type = r#"list[str | { preset = "..." }]"#,
        example = r#"
            deny-read = [{ preset = "known-secrets" }]
        "#
    )]
    pub deny_read: Option<Vec<FsEntry>>,

    /// Filesystem paths the sandboxed process can write to. Write implies read.
    ///
    /// Presets: `project`, `virtualenv`, `home`, `tmp`.
    #[option(
        default = "[]",
        value_type = r#"list[str | { preset = "..." }]"#,
        example = r#"
            allow-write = [{ preset = "project" }, { preset = "tmp" }]
        "#
    )]
    pub allow_write: Option<Vec<FsEntry>>,

    /// Filesystem paths to deny writing, even within allowed paths.
    ///
    /// Presets: `known-secrets`, `shell-configs`, `git-hooks`, `ide-configs`.
    #[option(
        default = "[]",
        value_type = r#"list[str | { preset = "..." }]"#,
        example = r#"
            deny-write = [{ preset = "shell-configs" }, { preset = "git-hooks" }, ".env"]
        "#
    )]
    pub deny_write: Option<Vec<FsEntry>>,

    /// Filesystem paths the sandboxed process can execute binaries from. Execute implies read.
    ///
    /// Presets: `python`, `system`.
    #[option(
        default = "[]",
        value_type = r#"list[str | { preset = "..." }]"#,
        example = r#"
            allow-execute = [{ preset = "python" }, { preset = "system" }]
        "#
    )]
    pub allow_execute: Option<Vec<FsEntry>>,

    /// Filesystem paths to deny executing from, even within allowed paths.
    #[option(
        default = "[]",
        value_type = r#"list[str | { preset = "..." }]"#,
        example = r#"
            deny-execute = ["./untrusted"]
        "#
    )]
    pub deny_execute: Option<Vec<FsEntry>>,

    /// Network access control.
    ///
    /// - `false` — deny all network access (default)
    /// - `true` — allow all network access
    /// - List of hosts/presets — allow specific hosts (phase 2)
    #[option(
        default = "false",
        value_type = r#"bool | list[str | { preset = "..." }]"#,
        example = r#"
            allow-net = false
        "#
    )]
    pub allow_net: Option<AllowNet>,

    /// Network hosts to deny, even if allowed by `allow-net`.
    #[option(
        default = "[]",
        value_type = r#"list[str | { preset = "..." }]"#,
        example = r#"
            deny-net = ["evil.example.com"]
        "#
    )]
    pub deny_net: Option<Vec<NetEntry>>,

    /// Environment variables visible to the sandboxed process.
    ///
    /// - `false` — deny all env vars (default)
    /// - `true` — pass all env vars
    /// - List of names/presets — pass specific variables
    #[option(
        default = "false",
        value_type = r#"bool | list[str | { preset = "..." }]"#,
        example = r#"
            allow-env = [{ preset = "standard" }, "DATABASE_URL"]
        "#
    )]
    pub allow_env: Option<AllowEnv>,

    /// Environment variables to hide, even if allowed by `allow-env`.
    ///
    /// Supports prefix wildcards (e.g., `"AWS_*"`).
    ///
    /// Presets: `known-secrets`.
    #[option(
        default = "[]",
        value_type = r#"list[str | { preset = "..." }]"#,
        example = r#"
            deny-env = [{ preset = "known-secrets" }, "AWS_*"]
        "#
    )]
    pub deny_env: Option<Vec<EnvEntry>>,

    /// Fail on unsupported platforms instead of warning and running unsandboxed.
    #[option(
        default = "false",
        value_type = "bool",
        example = r#"
            required = true
        "#
    )]
    pub required: Option<bool>,
}

impl SandboxOptions {
    /// Returns `true` if this configuration is "empty" — i.e., no fields are set.
    pub fn is_empty(&self) -> bool {
        self.allow_read.is_none()
            && self.deny_read.is_none()
            && self.allow_write.is_none()
            && self.deny_write.is_none()
            && self.allow_execute.is_none()
            && self.deny_execute.is_none()
            && self.allow_net.is_none()
            && self.deny_net.is_none()
            && self.allow_env.is_none()
            && self.deny_env.is_none()
            && self.required.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_sandbox_options_toml() {
        let toml_str = r#"
            allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
            allow-write = [{ preset = "project" }, { preset = "tmp" }]
            deny-write = [{ preset = "known-secrets" }, { preset = "shell-configs" }, ".env"]
            allow-execute = [{ preset = "python" }, { preset = "system" }]
            allow-net = false
            allow-env = [{ preset = "standard" }, "DATABASE_URL"]
            deny-env = [{ preset = "known-secrets" }]
        "#;

        let options: SandboxOptions = toml::from_str(toml_str).unwrap();

        assert_eq!(options.allow_read.as_ref().unwrap().len(), 3);
        assert_eq!(options.allow_write.as_ref().unwrap().len(), 2);
        assert_eq!(options.deny_write.as_ref().unwrap().len(), 3);
        assert_eq!(options.allow_execute.as_ref().unwrap().len(), 2);
        assert!(matches!(options.allow_net, Some(AllowNet::Bool(false))));
        assert!(matches!(options.allow_env, Some(AllowEnv::List(ref l)) if l.len() == 2));
        assert_eq!(options.deny_env.as_ref().unwrap().len(), 1);
        assert!(options.required.is_none());
    }

    #[test]
    fn deserialize_sandbox_options_allow_net_true() {
        let toml_str = r#"allow-net = true"#;
        let options: SandboxOptions = toml::from_str(toml_str).unwrap();
        assert!(matches!(options.allow_net, Some(AllowNet::Bool(true))));
    }

    #[test]
    fn deserialize_sandbox_options_allow_env_true() {
        let toml_str = r#"
            allow-env = true
            deny-env = ["SECRET_KEY"]
        "#;
        let options: SandboxOptions = toml::from_str(toml_str).unwrap();
        assert!(matches!(options.allow_env, Some(AllowEnv::Bool(true))));
        assert_eq!(options.deny_env.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn deserialize_sandbox_options_required() {
        let toml_str = r#"
            allow-read = [{ preset = "project" }]
            required = true
        "#;
        let options: SandboxOptions = toml::from_str(toml_str).unwrap();
        assert_eq!(options.required, Some(true));
    }

    #[test]
    fn deserialize_sandbox_options_unknown_field() {
        let toml_str = r#"
            allow-read = [{ preset = "system" }]
            allow-frobulate = true
        "#;
        let result: Result<SandboxOptions, _> = toml::from_str(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unknown field"), "error was: {err}");
    }

    #[test]
    fn deserialize_sandbox_options_unknown_preset() {
        let toml_str = r#"
            allow-read = [{ preset = "nonexistent" }]
        "#;
        let result: Result<SandboxOptions, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn sandbox_options_is_empty() {
        let options = SandboxOptions::default();
        assert!(options.is_empty());

        let options: SandboxOptions = toml::from_str(r#"allow-net = false"#).unwrap();
        assert!(!options.is_empty());
    }
}
