use serde::Serialize;
use std::io::{stdout, BufRead, Write};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseLogError {
    #[error("Invalid log line: {0}")]
    InvalidLogFormat(String),
}

pub trait LBLogParser {
    type Log<'input>: Serialize;

    fn parse<'input>(&self, log: &'input [u8]) -> Result<Self::Log<'input>, ParseLogError>;
}

pub fn repl<T: LBLogParser, R: BufRead>(mut reader: R, parser: T) -> anyhow::Result<()> {
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
