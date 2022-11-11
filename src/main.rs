mod alb;
mod classic_lb;
mod parse;

use crate::classic_lb::LogParser;
use std::io::{stdin, stdout, BufRead, BufWriter, Write};

use anyhow::Result;

fn main() -> Result<()> {
    let stdin = stdin();
    let mut stdin = stdin.lock();

    let mut buffer = Vec::new();
    let parser = LogParser::new();

    let stdout = stdout();
    let stdout = stdout.lock();
    let mut stdout = BufWriter::new(stdout);

    while stdin.read_until(b'\n', &mut buffer)? > 0 {
        let log = parser.parse(&buffer)?;
        serde_json::to_writer(&mut stdout, &log)?;
        stdout.write(b"\n")?;
        buffer.clear();
    }

    Ok(())
}
