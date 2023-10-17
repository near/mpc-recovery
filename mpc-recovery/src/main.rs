use clap::Parser;
use mpc_recovery::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    mpc_recovery::run(Cli::parse()).await
}
