mod alb;
mod classic_lb;
mod parse;

use crate::alb::LogParser as ALBLogParser;
use crate::classic_lb::LogParser as ClassicLBLogParser;
use crate::parse::repl;
use anyhow::Result;
use clap::{Parser, ValueEnum};

#[derive(Parser)]
#[command(about)]
struct Args {
    /// Type of load balancer
    #[arg(value_enum, short, long, default_value_t = Type::Alb)]
    r#type: Type,
}

#[derive(ValueEnum, Clone)]
enum Type {
    Alb,
    ClassicLb,
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.r#type {
        Type::Alb => repl(ALBLogParser::new())?,
        Type::ClassicLb => repl(ClassicLBLogParser::new())?,
    }

    Ok(())
}
