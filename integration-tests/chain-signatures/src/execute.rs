use std::path::Path;

use anyhow::{anyhow, Context};
use async_process::{Child, Command, ExitStatus, Stdio};

const PACKAGE_CONTRACT: &str = "mpc-contract";
const PACKAGE_MULTICHAIN: &str = "mpc-recovery-node";
const TARGET_CONTRACT: &str = "wasm32-unknown-unknown";

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

async fn build_package(
    release: bool,
    package: &str,
    target: Option<&str>,
    target_dir: Option<impl AsRef<Path>>,
) -> anyhow::Result<ExitStatus> {
    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("--package")
        .arg(package)
        .envs(std::env::vars())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    if release {
        cmd.arg("--release");
    }

    if let Some(target) = target {
        cmd.arg("--target").arg(target);
    }

    if let Some(target_dir) = target_dir {
        cmd.arg("--target-dir").arg(target_dir.as_ref().as_os_str());
    }

    Ok(cmd.spawn()?.status().await?)
}

pub async fn build_multichain(release: bool) -> anyhow::Result<ExitStatus> {
    build_package(
        release,
        PACKAGE_MULTICHAIN,
        None,
        Some(target_dir().ok_or_else(|| anyhow!("could not find /target while building node"))?),
    )
    .await
}

pub async fn build_multichain_contract() -> anyhow::Result<ExitStatus> {
    // We use a different target directory to stop the different rustflags between targets from clobbering the build cache
    build_package(
        true,
        PACKAGE_CONTRACT,
        Some(TARGET_CONTRACT),
        Some(
            target_dir()
                .ok_or_else(|| anyhow!("could not find /target while building contract"))?,
        ),
    )
    .await
}

pub fn executable(release: bool, executable: &str) -> Option<std::path::PathBuf> {
    let executable = target_dir()?
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
