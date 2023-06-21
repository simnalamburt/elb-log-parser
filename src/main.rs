mod alb;
mod classic_lb;
mod parse;

use std::fs::{metadata, File};
use std::io::{stdin, stdout, BufRead, BufReader, Write};

use anyhow::Result;
use clap::{Parser, ValueEnum};
use flate2::read::MultiGzDecoder;
use walkdir::WalkDir;

use crate::alb::LogParser as ALBLogParser;
use crate::classic_lb::LogParser as ClassicLBLogParser;
use crate::parse::LBLogParser;

#[derive(Parser)]
#[command(about, version, arg_required_else_help(true))]
struct Args {
    /// Type of load balancer.
    #[arg(value_enum, short, long, default_value_t = Type::Alb)]
    r#type: Type,

    /// Path of directory containing load balancer logs. To read from stdin, use "-".
    path: String,
}

#[derive(ValueEnum, Clone)]
enum Type {
    Alb,
    ClassicLb,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.path != "-" {
        match args.r#type {
            Type::Alb => walkdir::<ALBLogParser>(&args.path)?,
            Type::ClassicLb => walkdir::<ClassicLBLogParser>(&args.path)?,
        }
    } else {
        let stdin = stdin().lock();
        match args.r#type {
            Type::Alb => repl(stdin, ALBLogParser::new())?,
            Type::ClassicLb => repl(stdin, ClassicLBLogParser::new())?,
        }
    }

    Ok(())
}

fn walkdir<T: LBLogParser>(path: &str) -> Result<()> {
    // TODO: Apply parallelism
    for entry in WalkDir::new(path) {
        let entry = entry?; // TODO: Warn and skip instead of fail
        let path = entry.path();

        // ALB logs must ends with '.log.gz', and Classic LB logs must ends with '.log'
        if !path.to_str().map(|s| s.ends_with(T::EXT)).unwrap_or(false) {
            continue;
        }

        // Check for an empty file
        let metadata = metadata(path)?; // TODO: Warn and skip instead of fail
        if !metadata.is_file() || metadata.len() == 0 {
            continue;
        }

        let f = File::open(path)?; // TODO: Warn and skip instead of fail
        match T::TYPE {
            Type::Alb => repl(BufReader::new(MultiGzDecoder::new(f)), T::new())?,
            Type::ClassicLb => repl(BufReader::new(f), T::new())?,
        }
    }

    Ok(())
}

fn repl<T: LBLogParser, R: BufRead>(mut reader: R, parser: T) -> Result<()> {
    let mut buffer = Vec::new();

    let mut stdout = stdout().lock();
    while reader.read_until(b'\n', &mut buffer)? > 0 {
        {
            let log = parser.parse(&buffer)?;
            serde_json::to_writer(&mut stdout, &log)?;
        }
        stdout.write_all(b"\n")?;
        buffer.clear();
    }

    Ok(())
}
