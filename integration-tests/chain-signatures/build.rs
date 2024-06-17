use std::path::Path;
use std::{env, io};

use anyhow::Context;
use async_process::{Command, ExitStatus, Stdio};

const PACKAGE_MULTICHAIN: &str = "mpc-recovery-node";
const PACKAGE_CONTRACT: &str = "mpc-contract";
const TARGET_CONTRACT: &str = "wasm32-unknown-unknown";
const TARGET_FOLDER: &str = "target";

fn target_dir() -> io::Result<std::path::PathBuf> {
    let out_dir = env::var("OUT_DIR").map_err(|err| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("could not find OUT_DIR environment variable: {err:?}"),
        )
    })?;
    let mut out_dir = Path::new(&out_dir);
    loop {
        if out_dir.ends_with(TARGET_FOLDER) {
            break Ok(out_dir.to_path_buf());
        }

        match out_dir.parent() {
            Some(parent) => out_dir = parent,
            // We've reached the root directory and didn't find "target"
            None => {
                break Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "could not find /target",
                ))
            }
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
        .envs(env::vars())
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

async fn build_multichain(release: bool) -> anyhow::Result<ExitStatus> {
    let target_dir = target_dir().context("could not find /target while building node")?;
    build_package(release, PACKAGE_MULTICHAIN, None, Some(target_dir)).await
}

async fn build_multichain_contract(release: bool) -> anyhow::Result<ExitStatus> {
    let target_dir = target_dir().context("could not find /target while building contract")?;
    build_package(
        release,
        PACKAGE_CONTRACT,
        Some(TARGET_CONTRACT),
        Some(target_dir),
    )
    .await
}

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../chain-signatures/contract/");
    println!("cargo:rerun-if-changed=../../chain-signatures/keys/");
    println!("cargo:rerun-if-changed=../../chain-signatures/node/");

    let release = true;
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        build_multichain_contract(release).await?;
        build_multichain(release).await?;

        Ok(())
    })
}
