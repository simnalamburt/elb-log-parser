mod alb;
mod classic_lb;
mod parse;

use std::fs::{metadata, File};
use std::io::{stderr, stdin, stdout, BufRead, BufReader, IsTerminal, Write};
use std::thread;

use anyhow::{bail, Result};
use clap::{Parser, ValueEnum};
use crossbeam_channel::{unbounded, Sender};
use flate2::read::MultiGzDecoder;
use walkdir::{DirEntry, WalkDir};

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
        match args.r#type {
            Type::Alb => repl(ALBLogParser::new())?,
            Type::ClassicLb => repl(ClassicLBLogParser::new())?,
        }
    }

    Ok(())
}

// TODO: Warn and skip instead of fail on error
fn repl<T: LBLogParser>(parser: T) -> Result<()> {
    let mut buffer = Vec::new();
    let mut stdin = stdin().lock();
    let mut stdout = stdout().lock();
    while stdin.read_until(b'\n', &mut buffer)? > 0 {
        let log = parser.parse(&buffer)?;
        serde_json::to_writer(&mut stdout, &log)?;
        drop(log);
        stdout.write_all(b"\n")?;
        buffer.clear();
    }
    Ok(())
}

// TODO: Warn and skip instead of fail on error
fn walkdir<T: LBLogParser>(path: &str) -> Result<()> {
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
                let ret = || -> Result<()> {
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

                        let f = File::open(path)?;
                        match T::TYPE {
                            Type::Alb => {
                                produce(BufReader::new(MultiGzDecoder::new(f)), T::new(), &tx)?
                            }
                            Type::ClassicLb => produce(BufReader::new(f), T::new(), &tx)?,
                        }
                    }
                    Ok(())
                }();

                //
                // Error handling
                //
                let Err(err) = &ret else { return Ok(()) };

                if !stderr().is_terminal() {
                    eprintln!("Thread panicked with following error: {:?}", err);
                    return ret;
                }

                match err.downcast_ref::<parse::ParseLogError>() {
                    Some(parse::ParseLogError::InvalidLogFormat(log)) => {
                        match T::try_find_failed_position(log) {
                            None => {
                                eprintln!(
                                    "\
\x1b[31mThread panicked due to log parsing failure:\x1b[0m
    {}
",
                                    String::from_utf8_lossy(log).trim_end()
                                );
                            }
                            Some(idx) if idx < log.len() => {
                                eprintln!(
                                    "\
\x1b[31mThread panicked due to log parsing failure:\x1b[0m
    {}\x1b[1;91;4;31m{}\x1b[0m\x1b[38;5;238m{}\x1b[0m
",
                                    String::from_utf8_lossy(&log[..idx]),
                                    String::from_utf8_lossy(&log[idx..idx + 1]),
                                    String::from_utf8_lossy(&log[idx + 1..]).trim_end(),
                                );
                            }
                            Some(_) => {
                                eprintln!(
                                    "\
\x1b[31mThread panicked due to log parsing failure:\x1b[0m
    {} \x1b[91m(expected next input, but received none)\x1b[0m
",
                                    String::from_utf8_lossy(log).trim_end()
                                );
                            }
                        }
                    }
                    _ => eprintln!(
                        "\x1b[31mThread panicked with following error:\x1b[0m {:?}",
                        err
                    ),
                }

                ret
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
        let entry = entry?;
        t.send(entry)?;
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

// TODO: Warn and skip instead of fail on error
fn produce<T: LBLogParser, R: BufRead>(
    mut reader: R,
    parser: T,
    tx: &Sender<String>,
) -> Result<()> {
    let mut buffer = Vec::new();
    while reader.read_until(b'\n', &mut buffer)? > 0 {
        let log = parser.parse(&buffer)?;
        let json = serde_json::to_string(&log)?;
        drop(log);
        tx.send(json)?;
        buffer.clear();
    }
    Ok(())
}
