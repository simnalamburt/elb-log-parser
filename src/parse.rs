use serde::Serialize;
use thiserror::Error;

use crate::Type;

#[derive(Error, Debug)]
pub enum ParseLogError {
    #[error("Invalid log line: {0}")]
    InvalidLogFormat(String),
}

pub(crate) trait LBLogParser {
    type Log<'input>: Serialize;
    const EXT: &'static str;
    const TYPE: Type;

    fn new() -> Self;
    fn parse<'input>(&self, log: &'input [u8]) -> Result<Self::Log<'input>, ParseLogError>;
}
