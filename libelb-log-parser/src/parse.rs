use serde::{Serialize, Serializer, ser};
use thiserror::Error;

#[derive(Error, Clone, Debug)]
pub enum ParseLogError {
    #[error("Invalid log line: {}", String::from_utf8_lossy(.0))]
    InvalidLogFormat(Vec<u8>),
}

#[derive(Clone)]
pub enum LBType {
    Alb,
    ClassicLb,
}

pub trait LBLogParser {
    type Log<'input>: Serialize;

    const EXT: &'static str;
    const TYPE: LBType;
    const REGEX: &'static str;

    fn new() -> Self;
    fn parse<'input>(&self, log: &'input [u8]) -> Result<Self::Log<'input>, ParseLogError>;

    fn try_find_failed_position(log: &[u8]) -> Option<usize> {
        use regex_automata::Input;
        use regex_automata::dfa::{Automaton, dense::DFA};

        let dfa = DFA::new(Self::REGEX).unwrap();
        let mut s = dfa.start_state_forward(&Input::new(log)).unwrap();

        for (idx, &byte) in log.iter().enumerate() {
            s = dfa.next_state(s, byte);
            if dfa.is_dead_state(s) {
                return Some(idx);
            }
        }
        s = dfa.next_eoi_state(s);
        if dfa.is_dead_state(s) {
            return Some(log.len());
        }

        None
    }
}

pub(crate) fn bytes_ser<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let str = std::str::from_utf8(bytes)
        .map_err(|_| ser::Error::custom("log contains invalid UTF-8 characters"))?;
    serializer.serialize_str(str)
}

pub(crate) fn optional_bytes_ser<S>(
    optional_bytes: &Option<&[u8]>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match optional_bytes {
        Some(bytes) => bytes_ser(bytes, serializer),
        None => serializer.serialize_none(),
    }
}
