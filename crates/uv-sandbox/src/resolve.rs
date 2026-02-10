//! Resolve sandbox options from config into a concrete [`SandboxSpec`].

use crate::options::{AllowEnv, AllowNet};
use crate::presets::{PresetContext, resolve_env_filter};
use crate::settings::SandboxOptions;
use crate::spec::SandboxSpec;

/// Build a [`SandboxSpec`] from [`SandboxOptions`] and runtime context.
///
/// This expands all presets, resolves relative paths, filters environment
/// variables, and produces a fully concrete spec ready for the platform
/// sandbox implementation.
pub fn resolve_sandbox_spec(options: &SandboxOptions, context: &PresetContext) -> SandboxSpec {
    let allow_read = options
        .allow_read
        .as_deref()
        .map(|entries| context.expand_fs_entries(entries))
        .unwrap_or_default();

    let deny_read = options
        .deny_read
        .as_deref()
        .map(|entries| context.expand_fs_entries(entries))
        .unwrap_or_default();

    let allow_write = options
        .allow_write
        .as_deref()
        .map(|entries| context.expand_fs_entries(entries))
        .unwrap_or_default();

    let deny_write = options
        .deny_write
        .as_deref()
        .map(|entries| context.expand_fs_entries(entries))
        .unwrap_or_default();

    let allow_execute = options
        .allow_execute
        .as_deref()
        .map(|entries| context.expand_fs_entries(entries))
        .unwrap_or_default();

    let deny_execute = options
        .deny_execute
        .as_deref()
        .map(|entries| context.expand_fs_entries(entries))
        .unwrap_or_default();

    let allow_net = match &options.allow_net {
        Some(AllowNet::Bool(val)) => *val,
        Some(AllowNet::Hosts(_)) => {
            // Phase 2: domain filtering not yet implemented; treat as allow-all.
            true
        }
        None => false,
    };

    let env = resolve_env(options);

    SandboxSpec {
        allow_read,
        deny_read,
        allow_write,
        deny_write,
        allow_execute,
        deny_execute,
        allow_net,
        env,
    }
}

/// Resolve environment variable filtering.
///
/// Returns `None` if all env vars should be passed through.
/// Returns `Some(vec)` with the filtered list.
fn resolve_env(options: &SandboxOptions) -> Option<Vec<(String, String)>> {
    match (&options.allow_env, &options.deny_env) {
        // No config at all → deny all.
        (None, None) => Some(Vec::new()),
        // allow-env = true, no deny → pass all.
        (Some(AllowEnv::Bool(true)), None) => None,
        // allow-env = true, with deny list.
        (Some(AllowEnv::Bool(true)), Some(deny)) => {
            let current_env: Vec<_> = std::env::vars().collect();
            let allow_all: Vec<_> = current_env
                .iter()
                .map(|(k, _)| crate::options::EnvEntry::Name(k.clone()))
                .collect();
            Some(resolve_env_filter(&allow_all, deny, &current_env))
        }
        // allow-env = false → deny all (deny list is irrelevant).
        (Some(AllowEnv::Bool(false)), _) | (None, Some(_)) => Some(Vec::new()),
        // allow-env = list, optional deny.
        (Some(AllowEnv::List(allow)), deny_opt) => {
            let deny = deny_opt.as_deref().unwrap_or_default();
            let current_env: Vec<_> = std::env::vars().collect();
            Some(resolve_env_filter(allow, deny, &current_env))
        }
    }
}
