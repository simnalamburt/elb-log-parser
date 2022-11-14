mod alb;
mod classic_lb;
mod parse;

use std::fs::{metadata, File};
use std::io::{stdin, BufReader};

use crate::alb::LogParser as ALBLogParser;
use crate::classic_lb::LogParser as ClassicLBLogParser;
use crate::parse::repl;
use anyhow::Result;
use clap::{Parser, ValueEnum};
use flate2::read::GzDecoder;
use walkdir::WalkDir;

#[derive(Parser)]
#[command(about)]
struct Args {
    /// Type of load balancer.
    #[arg(value_enum, short, long, default_value_t = Type::Alb)]
    r#type: Type,

    /// Path of directory containing load balancer logs. If not present, reads from stdin.
    path: Option<String>,
}

#[derive(ValueEnum, Clone)]
enum Type {
    Alb,
    ClassicLb,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(path) = args.path {
        for entry in WalkDir::new(path) {
            let entry = entry?;
            let path = entry.path();

            if !path
                .to_str()
                .map(|s| s.ends_with(".log.gz"))
                .unwrap_or(false)
            {
                continue;
            }

            // Check for an empty file
            let metadata = metadata(path)?;
            if !metadata.is_file() || metadata.len() == 0 {
                continue;
            }

            // TODO: Apply parallelism
            let f = BufReader::new(GzDecoder::new(File::open(path)?));
            match args.r#type {
                Type::Alb => repl(f, ALBLogParser::new())?,
                Type::ClassicLb => repl(f, ClassicLBLogParser::new())?,
            }
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
