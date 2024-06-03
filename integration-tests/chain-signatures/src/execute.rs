use anyhow::Context;
use async_process::Child;

const PACKAGE_MULTICHAIN: &str = "mpc-recovery-node";

pub fn target_dir() -> Option<std::path::PathBuf> {
    let mut out_dir = std::path::Path::new(std::env!("OUT_DIR"));
    loop {
        if out_dir.ends_with("target") {
            break Some(out_dir.to_path_buf());
        }

        match out_dir.parent() {
            Some(parent) => out_dir = parent,
            None => break None, // We've reached the root directory and didn't find "target"
        }
    }
}

pub fn executable(release: bool, executable: &str) -> Option<std::path::PathBuf> {
    let executable = target_dir()?
        .join("native")
        .join(if release { "release" } else { "debug" })
        .join(executable);
    Some(executable)
}

pub fn spawn_multichain(
    release: bool,
    node: &str,
    cli: mpc_recovery_node::cli::Cli,
) -> anyhow::Result<Child> {
    let executable = executable(release, PACKAGE_MULTICHAIN)
        .with_context(|| format!("could not find target dir while starting {node} node"))?;

    async_process::Command::new(&executable)
        .args(cli.into_str_args())
        .env("RUST_LOG", "mpc_recovery_node=INFO")
        .envs(std::env::vars())
        .stdout(async_process::Stdio::inherit())
        .stderr(async_process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to run {node} node: {}", executable.display()))
}
