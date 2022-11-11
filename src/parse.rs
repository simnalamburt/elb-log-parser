use serde::Serialize;
use std::io::{stdin, stdout, BufRead, BufWriter, Write};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseLogError {
    #[error("Invalid log line: {0:?}")]
    InvalidLogFormat(Vec<u8>),
}

pub trait LBLogParser {
    type Log<'input>: Serialize;

    fn parse<'input>(&self, log: &'input [u8]) -> Result<Self::Log<'input>, ParseLogError>;
}

pub fn repl<T: LBLogParser>(parser: T) -> anyhow::Result<()> {
    let stdin = stdin();
    let mut stdin = stdin.lock();

    let mut buffer = Vec::new();

    let stdout = stdout();
    let stdout = stdout.lock();
    let mut stdout = BufWriter::new(stdout);
    while stdin.read_until(b'\n', &mut buffer)? > 0 {
        {
            let log = parser.parse(&buffer)?;
            serde_json::to_writer(&mut stdout, &log)?;
        }
        stdout.write_all(b"\n")?;
        buffer.clear();
    }

    Ok(())
}
