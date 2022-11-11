use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseLogError {
    #[error("Invalid log line: {0:?}")]
    InvalidLogFormat(Vec<u8>),
}
