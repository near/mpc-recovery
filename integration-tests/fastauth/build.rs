use std::path::Path;
use std::{env, io};

use anyhow::Context;
use async_process::{Command, ExitStatus, Stdio};

const PACKAGE: &str = "mpc-recovery";
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

    if let Some(target_dir) = target_dir {
        cmd.arg("--target-dir").arg(target_dir.as_ref().as_os_str());
    }

    Ok(cmd.spawn()?.status().await?)
}

pub async fn build_mpc(release: bool) -> anyhow::Result<ExitStatus> {
    build_package(
        release,
        PACKAGE,
        Some(target_dir().context("could not find /target while building mpc-recovery")?),
    )
    .await
}

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../mpc-recovery/");

    #[cfg(not(feature = "flamegraph"))]
    {
        let release = true;
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            build_mpc(release).await?;
            Ok(())
        })
    }
}
