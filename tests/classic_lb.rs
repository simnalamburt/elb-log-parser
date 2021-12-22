use elb_log_parser::classic_lb::LogParser;

// TODO: Test Classic LB v1 and v2 log formats

/*
#[test]
fn test_classic_lb_log_parse() {
    let log = LogParser::new().parse(
        r#"2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000086 0.001048 0.001337 200 200 0 57"# //  "GET https://www.example.com:443/ HTTP/1.1" "curl/7.38.0" DHE-RSA-AES128-SHA TLSv1.2
    ).unwrap();

    assert_eq!(log.timestamp, "2015-05-13T23:39:43.945958Z");
    assert_eq!(log.elb, "my-loadbalancer");
    assert_eq!(log.client, "192.168.131.39:2817");
    assert_eq!(log.backend, "10.0.0.1:80");
    assert_eq!(log.request_processing_time, "0.000086");
    assert_eq!(log.backend_processing_time, "0.001048");
    assert_eq!(log.response_processing_time, "0.001337");
    assert_eq!(log.elb_status_code, "200");
    assert_eq!(log.backend_status_code, "200");
    assert_eq!(log.received_bytes, "0");
    assert_eq!(log.sent_bytes, "57");
    // TODO
}
*/
