use std::env;
use std::path::PathBuf;

use clap::CommandFactory;
use clap_complete::{
    generate_to,
    shells::{Bash, Fish, Zsh},
};

// import `Args` struct.
include!("src/cli.rs");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let mut cmd = Args::command();

    generate_to(Bash, &mut cmd, env!("CARGO_PKG_NAME"), &out_dir)?;
    generate_to(Zsh, &mut cmd, env!("CARGO_PKG_NAME"), &out_dir)?;
    generate_to(Fish, &mut cmd, env!("CARGO_PKG_NAME"), &out_dir)?;

    Ok(())
}
