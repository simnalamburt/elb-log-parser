use lalrpop_util::lalrpop_mod;

lalrpop_mod!(pub classic_lb); // synthesized by LALRPOP

// TODO: Test Classic LB v1 and v2 log formats

#[test]
fn test_iso8601() {
    assert!(classic_lb::TimestampParser::new().parse("2021-11-22T01:58:01.532018Z").is_ok());
}
