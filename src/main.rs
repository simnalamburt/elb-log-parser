use std::io::{stdin, stdout, Write, BufRead};

use regex::Regex;
use serde::Serialize;

#[derive(Serialize)]
struct Log<'a> {
    time: &'a str,
    elb: &'a str,
    client_ip: &'a str,
    client_port: &'a str,
    backend_ip: &'a str,
    backend_port: &'a str,
    request_processing_time: &'a str,
    backend_processing_time: &'a str,
    response_processing_time: &'a str,
    elb_status_code: &'a str,
    backend_status_code: &'a str,
    received_bytes: &'a str,
    sent_bytes: &'a str,
    http_method: &'a str,
    url: &'a str,
    http_version: &'a str,
    user_agent: &'a str,
    ssl_cipher: &'a str,
    ssl_protocol: &'a str,
}

struct Parser {
    regex: Regex,
}

impl Parser {
    fn new() -> Self {
        Self {
            // https://docs.aws.amazon.com/en_us/elasticloadbalancing/latest/classic/access-log-collection.html#access-log-entry-syntax
            regex: Regex::new(r#"(?x)
                ^
                ([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}Z)   # time
                \x20
                ([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9-])?)         # elb
                \x20
                ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})    # client ip
                :
                ([0-9]{1,5})                                        # client port
                \x20
                ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})    # backend ip
                :
                ([0-9]{1,5}|-)                                      # backend port
                \x20
                ([0-9]+\.[0-9]+|-1)                                 # request processing time
                \x20
                ([0-9]+\.[0-9]+|-1)                                 # backend processing time
                \x20
                ([0-9]+\.[0-9]+|-1)                                 # response processing time
                \x20
                ([0-9]{3}|-)                                        # elb status code
                \x20
                ([0-9]{3}|-)                                        # backend status code
                \x20
                ([0-9]+)                                            # received bytes
                \x20
                ([0-9]+)                                            # sent bytes
                \x20
                "
                    (-|[A-Z]+)                                      # http method
                    \x20
                    ((?:[^\n\\"]|\\"|\\\\|\\x[0-9a-f]{8})*)         # URL
                    \x20
                    (-\x20|HTTP/[0-9.]+)                            # http version
                "
                \x20
                ("(?:[^\n\\"]|\\"|\\\\|\\x[0-9a-f]{8})*")           # user agent
                \x20
                ([0-9A-Z-]+)                                        # ssl cipher
                \x20
                (TLSv[0-9.]+|-)                                     # ssl protocol
                $
            "#).unwrap()
        }
    }

    fn log_to_json(&self, log: &str) -> String {
        let caps = self.regex.captures(log).unwrap();
        let log = Log {
            time:                       &caps[1],
            elb:                        &caps[2],
            client_ip:                  &caps[3],
            client_port:                &caps[4],
            backend_ip:                 &caps[5],
            backend_port:               &caps[6],
            request_processing_time:    &caps[7],
            backend_processing_time:    &caps[8],
            response_processing_time:   &caps[9],
            elb_status_code:            &caps[10],
            backend_status_code:        &caps[11],
            received_bytes:             &caps[12],
            sent_bytes:                 &caps[13],
            http_method:                &caps[14],
            url:                        &caps[15],
            http_version:               &caps[16],
            user_agent:                 &caps[17],
            ssl_cipher:                 &caps[18],
            ssl_protocol:               &caps[19],
        };

        serde_json::to_string(&log).unwrap()
    }
}

fn main() {
    let stdin = stdin();
    let stdout = stdout();

    let stdin = stdin.lock();
    let mut stdout = stdout.lock();

    let parser = Parser::new();
    for line in stdin.lines() {
        let line = line.unwrap();
        let json = parser.log_to_json(&line);
        writeln!(stdout, "{}", json).unwrap();
    }
}

#[test]
fn test_parser() {
    let parser = Parser::new();

    assert_eq!(
        parser.log_to_json(r#"2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000073 0.001048 0.000057 200 200 0 29 "GET http://www.example.com:80/ HTTP/1.1" "curl/7.38.0" - -"#),
        r#"{"time":"2015-05-13T23:39:43.945958Z","elb":"my-loadbalancer","client_ip":"192.168.131.39","client_port":"2817","backend_ip":"10.0.0.1","backend_port":"80","request_processing_time":"0.000073","backend_processing_time":"0.001048","response_processing_time":"0.000057","elb_status_code":"200","backend_status_code":"200","received_bytes":"0","sent_bytes":"29","http_method":"GET","url":"http://www.example.com:80/","http_version":"HTTP/1.1","user_agent":"\"curl/7.38.0\"","ssl_cipher":"-","ssl_protocol":"-"}"#,
    );
    assert_eq!(
        parser.log_to_json(r#"2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000086 0.001048 0.001337 200 200 0 57 "GET https://www.example.com:443/ HTTP/1.1" "curl/7.38.0" DHE-RSA-AES128-SHA TLSv1.2"#),
        r#"{"time":"2015-05-13T23:39:43.945958Z","elb":"my-loadbalancer","client_ip":"192.168.131.39","client_port":"2817","backend_ip":"10.0.0.1","backend_port":"80","request_processing_time":"0.000086","backend_processing_time":"0.001048","response_processing_time":"0.001337","elb_status_code":"200","backend_status_code":"200","received_bytes":"0","sent_bytes":"57","http_method":"GET","url":"https://www.example.com:443/","http_version":"HTTP/1.1","user_agent":"\"curl/7.38.0\"","ssl_cipher":"DHE-RSA-AES128-SHA","ssl_protocol":"TLSv1.2"}"#,
    );
    assert_eq!(
        parser.log_to_json(r#"2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.001069 0.000028 0.000041 - - 82 305 "- - - " "-" - -"#),
        r#"{"time":"2015-05-13T23:39:43.945958Z","elb":"my-loadbalancer","client_ip":"192.168.131.39","client_port":"2817","backend_ip":"10.0.0.1","backend_port":"80","request_processing_time":"0.001069","backend_processing_time":"0.000028","response_processing_time":"0.000041","elb_status_code":"-","backend_status_code":"-","received_bytes":"82","sent_bytes":"305","http_method":"-","url":"-","http_version":"- ","user_agent":"\"-\"","ssl_cipher":"-","ssl_protocol":"-"}"#,
    );
    assert_eq!(
        parser.log_to_json(r#"2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.001065 0.000015 0.000023 - - 57 502 "- - - " "-" ECDHE-ECDSA-AES128-GCM-SHA256 TLSv1.2"#),
        r#"{"time":"2015-05-13T23:39:43.945958Z","elb":"my-loadbalancer","client_ip":"192.168.131.39","client_port":"2817","backend_ip":"10.0.0.1","backend_port":"80","request_processing_time":"0.001065","backend_processing_time":"0.000015","response_processing_time":"0.000023","elb_status_code":"-","backend_status_code":"-","received_bytes":"57","sent_bytes":"502","http_method":"-","url":"-","http_version":"- ","user_agent":"\"-\"","ssl_cipher":"ECDHE-ECDSA-AES128-GCM-SHA256","ssl_protocol":"TLSv1.2"}"#,
    );
}
