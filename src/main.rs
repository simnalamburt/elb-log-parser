mod alb;
mod classic_lb;
mod parse;

use crate::alb::LogParser as ALBLogParser;
use crate::classic_lb::LogParser as ClassicLBLogParser;
use anyhow::Result;
use clap::{Parser, ValueEnum};
use std::io::{stdin, stdout, BufRead, BufWriter, Write};

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
    let stdin = stdin();
    let mut stdin = stdin.lock();

    let mut buffer = Vec::new();

    let stdout = stdout();
    let stdout = stdout.lock();
    let mut stdout = BufWriter::new(stdout);

    match args.r#type {
        Type::Alb => {
            let parser = ALBLogParser::new();
            while stdin.read_until(b'\n', &mut buffer)? > 0 {
                let log = parser.parse(&buffer)?;
                serde_json::to_writer(&mut stdout, &log)?;
                stdout.write(b"\n")?;
                buffer.clear();
            }
        }
        Type::ClassicLb => {
            let parser = ClassicLBLogParser::new();
            while stdin.read_until(b'\n', &mut buffer)? > 0 {
                let log = parser.parse(&buffer)?;
                serde_json::to_writer(&mut stdout, &log)?;
                stdout.write(b"\n")?;
                buffer.clear();
            }
        }
    };

    Ok(())
}
