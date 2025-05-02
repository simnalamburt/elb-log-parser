mod alb;
mod classic_lb;
mod parse;

use std::fs::{File, metadata};
use std::io::{BufRead, BufReader, IsTerminal, Write, stderr, stdin, stdout};
use std::thread;

use anyhow::{Result, bail};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum, builder::ValueHint};
use clap_complete::{Shell, generate};
use crossbeam_channel::unbounded;
use flate2::read::MultiGzDecoder;
use walkdir::{DirEntry, WalkDir};

use crate::alb::LogParser as ALBLogParser;
use crate::classic_lb::LogParser as ClassicLBLogParser;
use crate::parse::{LBLogParser, ParseLogError};

#[derive(Parser)]
#[command(
    about,
    version,
    arg_required_else_help = true,
    args_conflicts_with_subcommands = true
)]
struct Args {
    /// Type of load balancer.
    #[arg(value_enum, short, long, default_value_t = Type::Alb)]
    r#type: Type,

    #[command(flatten)]
    config: Config,

    /// Path of directory containing load balancer logs. To read from stdin, use "-".
    #[arg(required = true, value_hint = ValueHint::DirPath, allow_hyphen_values = true)]
    path: Option<String>,

    /// Subcommands
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(ValueEnum, Clone)]
enum Type {
    Alb,
    ClassicLb,
}

#[derive(Parser, Clone, Copy)]
struct Config {
    /// Skip parsing errors.
    #[arg(long)]
    skip_parse_errors: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate shell completion script for specified shell
    #[command(arg_required_else_help = true)]
    Completion {
        #[arg(value_enum)]
        shell: Shell,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Handle shell completion
    if let Some(Commands::Completion { shell }) = args.command {
        let mut cmd = Args::command();
        let bin_name = env!("CARGO_PKG_NAME");
        generate(shell, &mut cmd, bin_name, &mut stdout());
        return Ok(());
    }

    // Otherwise, args.path must exist
    let Some(path) = args.path else {
        unreachable!()
    };
    match args.r#type {
        Type::Alb => main_of::<ALBLogParser>(&path, args.config)?,
        Type::ClassicLb => main_of::<ClassicLBLogParser>(&path, args.config)?,
    }
    Ok(())
}

fn main_of<T: LBLogParser>(path: &str, config: Config) -> Result<()> {
    if path != "-" {
        walkdir::<T>(path, config)
    } else {
        let stdin = stdin().lock();
        let mut stdout = stdout().lock();
        for_each_parsed_lines::<T>(stdin, config, |log| {
            serde_json::to_writer(&mut stdout, log)?;
            stdout.write_all(b"\n")?;
            Ok(())
        })
    }
}

fn walkdir<T: LBLogParser>(path: &str, config: Config) -> Result<()> {
    //
    // 1 walkdir thread  --------> N parsing/serializing worker threads --------> 1 output thread
    //   (main thread)     (t,r)            `worker_threads`             (tx,rx)   `output_thread`
    //
    let (t, r) = unbounded::<DirEntry>();
    let (tx, rx) = unbounded::<String>();

    // Create parsing/serializing worker threads
    let worker_threads: Vec<_> = (0..thread::available_parallelism()?.get())
        .map(|_| {
            let r = r.clone();
            let tx = tx.clone();
            thread::spawn(move || -> Result<()> {
                while let Ok(entry) = r.recv() {
                    let path = entry.path();

                    // ALB logs must ends with '.log.gz', and Classic LB logs must ends with '.log'
                    if !path.to_str().map(|s| s.ends_with(T::EXT)).unwrap_or(false) {
                        continue;
                    }

                    // Check for an empty file
                    let metadata = metadata(path)?;
                    if !metadata.is_file() || metadata.len() == 0 {
                        continue;
                    }

                    let file = File::open(path)?;
                    let reader: Box<dyn BufRead> = match T::TYPE {
                        Type::Alb => Box::new(BufReader::new(MultiGzDecoder::new(file))),
                        Type::ClassicLb => Box::new(BufReader::new(file)),
                    };
                    for_each_parsed_lines::<T>(reader, config, |log| {
                        let json = serde_json::to_string(&log)?;
                        tx.send(json)?;
                        Ok(())
                    })?;
                }
                Ok(())
            })
        })
        .collect();
    drop(r);
    drop(tx);

    // Create an output thread
    let output_thread = thread::spawn(move || -> Result<()> {
        let mut stdout = stdout().lock();

        while let Ok(json) = rx.recv() {
            writeln!(stdout, "{json}")?;
        }
        drop(rx);
        Ok(())
    });

    // TODO: Apply parallelism
    for entry in WalkDir::new(path) {
        t.send(entry?)?;
    }
    drop(t);

    // TODO: handle result
    if let Err(panic) = output_thread.join() {
        bail!("Thread panicked with error: {:?}", panic);
    }
    for thread in worker_threads {
        if let Err(panic) = thread.join() {
            bail!("Thread panicked with error: {:?}", panic);
        }
    }

    Ok(())
}

fn for_each_parsed_lines<T: LBLogParser>(
    mut reader: impl BufRead,
    config: Config,
    mut callback: impl FnMut(&T::Log<'_>) -> Result<()>,
) -> Result<()> {
    let parser = T::new();
    let mut buffer = Vec::new();
    while reader.read_until(b'\n', &mut buffer)? > 0 {
        let result = parser.parse(&buffer);
        let log = match &result {
            Ok(log) => log,

            //
            // Error handling
            //
            Err(err) => {
                reporter::<T>(config, err);

                if !config.skip_parse_errors {
                    return Err(err.clone().into());
                }
                drop(result);
                buffer.clear();
                continue;
            }
        };

        callback(log)?;

        drop(result);
        buffer.clear();
    }
    Ok(())
}

fn reporter<T: LBLogParser>(config: Config, err: &ParseLogError) {
    if !stderr().is_terminal() {
        if config.skip_parse_errors {
            eprintln!("Skipping error: {}", err);
        } else {
            eprintln!("Error: {}", err);
        }
    } else {
        let msg = if config.skip_parse_errors {
            "\x1b[33mFailed to parse following line, skipping:\x1b[0m"
        } else {
            "\x1b[31mThread panicked due to parsing failure:\x1b[0m"
        };

        let ParseLogError::InvalidLogFormat(log) = err;

        match T::try_find_failed_position(log) {
            None => eprintln!("{}\n    {}\n", msg, String::from_utf8_lossy(log).trim_end()),
            Some(idx) if idx < log.len() => eprintln!(
                "{}\n    {}\x1b[1;91;4;31m{}\x1b[0m\x1b[38;5;238m{}\x1b[0m\n",
                msg,
                // TODO: Properly detect the border of grapheme clusters around 'idx'
                String::from_utf8_lossy(&log[..idx]),
                String::from_utf8_lossy(&log[idx..idx + 1]),
                String::from_utf8_lossy(&log[idx + 1..]).trim_end(),
            ),
            Some(_) => eprintln!(
                "{}\n    {} \x1b[91m(expected next input, but received none)\x1b[0m\n",
                msg,
                String::from_utf8_lossy(log).trim_end()
            ),
        }
    }
}
