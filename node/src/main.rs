use clap::Parser;
use mpc_recovery_node::cli::Cli;

fn main() -> anyhow::Result<()> {
    mpc_recovery_node::cli::run(Cli::parse())
}
