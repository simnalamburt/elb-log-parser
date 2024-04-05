use serde::{ser, Serialize, Serializer};
use thiserror::Error;

use crate::Type;

#[derive(Error, Debug)]
pub enum ParseLogError {
    #[error("Invalid log line: {}", String::from_utf8_lossy(.0))]
    InvalidLogFormat(Vec<u8>),
}

pub(crate) trait LBLogParser {
    type Log<'input>: Serialize;

    const EXT: &'static str;
    const TYPE: Type;
    const REGEX: &'static str;

    fn new() -> Self;
    fn parse<'input>(&self, log: &'input [u8]) -> Result<Self::Log<'input>, ParseLogError>;
}

pub(crate) fn bytes_ser<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let str = std::str::from_utf8(bytes)
        .map_err(|_| ser::Error::custom("log contains invalid UTF-8 characters"))?;
    serializer.serialize_str(str)
}
