pub use options::{
    AllowEnv, AllowNet, EnvEntry, EnvPreset, FsEntry, FsPreset, NetEntry, NetPreset,
};
pub use presets::PresetContext;
pub use resolve::resolve_sandbox_spec;
pub use settings::SandboxOptions;
pub use spawn::apply_sandbox;
pub use spec::SandboxSpec;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;

mod options;
pub mod presets;
mod resolve;
mod settings;
pub mod spawn;
pub mod spec;
