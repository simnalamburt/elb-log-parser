// TODO: Test Classic LB v1 and v2 log formats
use elb_log_parser::classic_lb::{TimestampParser, NameParser};

#[test]
fn test_timestamp() {
    assert!(TimestampParser::new().parse("2021-11-22T01:58:01.532018Z").is_ok());
}

#[test]
fn test_name() {
    assert!(NameParser::new().parse("a").is_ok());
    assert!(NameParser::new().parse("ELB-NAME").is_ok());

    assert!(NameParser::new().parse("").is_err());
    assert!(NameParser::new().parse("-").is_err());
    assert!(NameParser::new().parse("a-").is_err());
    assert!(NameParser::new().parse("-a").is_err());
    assert!(NameParser::new().parse("ELB_NAME").is_err());
    assert!(NameParser::new().parse("asd*asd").is_err());
    assert!(NameParser::new().parse("asd가asd").is_err());
    assert!(NameParser::new().parse("TOO-LONG-ELB-NAME-TOO-LONG-ELB-NAME-TOO-LONG-ELB-NAME-TOO-LONG-ELB-NAME-TOO-LONG-ELB-NAME").is_err());
}
