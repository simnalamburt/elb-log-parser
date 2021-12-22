use std::str::CharIndices;
use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok<'input> {
    String(&'input str),
}

#[derive(PartialEq, Eq)]
enum LexerState {
    Normal,
    Word { start: usize },
    Quoted { start: usize },
    QuotedSlash { start: usize },
    Finished,
}

pub struct Lexer<'input> {
    input: &'input str,
    chars: CharIndices<'input>,
    state: LexerState,
}

impl<'input> Lexer<'input> {
    pub fn new(input: &'input str) -> Self {
        Lexer {
            input,
            chars: input.char_indices(),
            state: LexerState::Normal,
        }
    }
}

impl<'input> Iterator for Lexer<'input> {
    type Item = (usize, Tok<'input>, usize);

    fn next(&mut self) -> Option<Self::Item> {
        use LexerState::{Normal, Word, Quoted, QuotedSlash, Finished};

        let mut ret = None;
        while ret.is_none() && self.state != Finished {
            let input = self.chars.next();

            ret = match (&self.state, input) {
                (Normal, ..) => None,

                (&Word { start }, None) => Some(start..self.input.len()),
                (&Word { start }, Some((i, ' ' | '\t' | '\n' | '\r'))) => Some(start..i),
                (Word { .. }, Some(..)) => None,

                (&Quoted { start }, None) => Some(start..self.input.len()),
                (&Quoted { start }, Some((i, '"'))) => Some(start..i+1),
                (Quoted { .. }, Some(..)) => None,

                (&QuotedSlash { start }, None) => Some(start..self.input.len()),
                (QuotedSlash { .. }, Some(..)) => None,

                (Finished, _) => unreachable!(),
            };

            self.state = match (&self.state, input) {
                (.., None) => Finished,

                (Normal, Some((_, ' ' | '\t' | '\n' | '\r'))) => Normal, // same
                (Normal, Some((start, '"'))) => Quoted { start },
                (Normal, Some((start, _))) => Word { start },

                (Word { .. }, Some((_, ' ' | '\t' | '\n' | '\r'))) => Normal,
                (&Word { start }, Some(_)) => Word { start }, // same

                (Quoted { .. }, Some((_, '"'))) => Normal,
                (&Quoted { start }, Some((_, '\\'))) => QuotedSlash { start },
                (&Quoted { start }, Some(_)) => Quoted { start }, // same
                (&QuotedSlash { start }, Some(_)) => Quoted { start },

                (Finished, _) => unreachable!(),
            }
        }
        ret.map(|Range { start, end }| (start, Tok::String(&self.input[start..end]), end))
    }
}

#[test]
fn test_lexer() {
    fn t<const N: usize>(input: &str, expected: [&str; N]) {
        assert_eq!(Lexer::new(input).map(|(_, Tok::String(s), _)| s).collect::<Vec<_>>(), expected)
    }

    t("", []);
    t("hi", ["hi"]);
    t(r#" abc "Hello, world!" yo hoho"#, ["abc", "\"Hello, world!\"", "yo", "hoho"]);
    t(r#"word"word"#, ["word\"word"]);
    t(r#"yolo "Swa\g \" ho" "quo"#, ["yolo", r#""Swa\g \" ho""#, r#""quo"#]);
    t(r#"yo\lo "Swa\g \" ho" "quo\"#, [r#"yo\lo"#, r#""Swa\g \" ho""#, r#""quo\"#]);
}
