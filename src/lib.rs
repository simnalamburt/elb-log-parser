use lalrpop_util::lalrpop_mod;

lalrpop_mod!(pub classic_load_balancer); // synthesized by LALRPOP

#[test]
fn test_classic_load_balancer() {
    // TODO: Test Classic LB v1 and v2 log formats
    assert!(classic_load_balancer::TermParser::new().parse("22").is_ok());
    assert!(classic_load_balancer::TermParser::new().parse("(22)").is_ok());
    assert!(classic_load_balancer::TermParser::new().parse("((((22))))").is_ok());
    assert!(classic_load_balancer::TermParser::new().parse("((22)").is_err());
}
