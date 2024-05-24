use std::path::{Path, PathBuf};

use anyhow::Context;
use async_process::{Command, ExitStatus, Stdio};
use tokio::runtime::Runtime;

use mpc_recovery::Cli;

const PACKAGE: &str = "mpc-recovery";
const PACKAGE_MULTICHAIN: &str = "mpc-recovery-node";
const PACKAGE_CONTRACT: &str = "mpc-contract";
const TARGET_CONTRACT: &str = "wasm32-unknown-unknown";
pub const TARGET_CONTRACT_DIR: &str = "../target/seperate_wasm";

/// NodeProcess holds onto the respective handles such that on drop, it will clean
/// the running process, task, or thread.
pub enum NodeProcess {
    Subprocess(async_process::Child),
    Threaded(std::thread::JoinHandle<anyhow::Result<()>>),
}

pub fn executable(release: bool, executable: &str) -> Option<PathBuf> {
    let executable = target_dir()?
        .join(if release { "release" } else { "debug" })
        .join(executable);
    Some(executable)
}

fn target_dir() -> Option<PathBuf> {
    let mut out_dir = Path::new(std::env!("OUT_DIR"));
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
    target_dir: Option<&str>,
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
        cmd.arg("--target-dir").arg(target_dir);
    }

    Ok(cmd.spawn()?.status().await?)
}

pub async fn build(release: bool) -> anyhow::Result<ExitStatus> {
    build_package(release, PACKAGE, None, None).await
}

pub async fn build_multichain(release: bool) -> anyhow::Result<ExitStatus> {
    build_package(release, PACKAGE_MULTICHAIN, None, None).await
}

pub async fn build_multichain_contract() -> anyhow::Result<ExitStatus> {
    // We use a different target directory to stop the different rustflags between targets from clobbering the build cache
    build_package(
        true,
        PACKAGE_CONTRACT,
        Some(TARGET_CONTRACT),
        Some(TARGET_CONTRACT_DIR),
    )
    .await
}

pub async fn spawn(release: bool, node: &str, cli: Cli) -> anyhow::Result<NodeProcess> {
    if cfg!(feature = "flamegraph") {
        let handle: std::thread::JoinHandle<anyhow::Result<()>> = std::thread::spawn(|| {
            let rt = Runtime::new()?;
            rt.block_on(async move {
                mpc_recovery::run(cli).await?;
                anyhow::Result::<(), anyhow::Error>::Ok(())
            })
            .unwrap();
            Ok(())
        });

        return Ok(NodeProcess::Threaded(handle));
    }

    let executable = executable(release, PACKAGE)
        .with_context(|| format!("could not find target dir while starting {node} node"))?;
    let child = Command::new(executable)
        .args(cli.into_str_args())
        .env("RUST_LOG", "mpc_recovery=INFO")
        .envs(std::env::vars())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to execute {node} node"))?;

    Ok(NodeProcess::Subprocess(child))
}
