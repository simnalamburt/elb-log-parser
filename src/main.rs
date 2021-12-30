use std::io::{stdin, stdout, BufRead, BufWriter, Write};

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
            regex: Regex::new(
                r#"(?x)
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
            "#,
            )
            .unwrap(),
        }
    }

    fn parse<'input>(&self, log: &'input str) -> Log<'input> {
        let caps = self.regex.captures(log).unwrap();
        Log {
            time: caps.get(1).unwrap().as_str(),
            elb: caps.get(2).unwrap().as_str(),
            client_ip: caps.get(3).unwrap().as_str(),
            client_port: caps.get(4).unwrap().as_str(),
            backend_ip: caps.get(5).unwrap().as_str(),
            backend_port: caps.get(6).unwrap().as_str(),
            request_processing_time: caps.get(7).unwrap().as_str(),
            backend_processing_time: caps.get(8).unwrap().as_str(),
            response_processing_time: caps.get(9).unwrap().as_str(),
            elb_status_code: caps.get(10).unwrap().as_str(),
            backend_status_code: caps.get(11).unwrap().as_str(),
            received_bytes: caps.get(12).unwrap().as_str(),
            sent_bytes: caps.get(13).unwrap().as_str(),
            http_method: caps.get(14).unwrap().as_str(),
            url: caps.get(15).unwrap().as_str(),
            http_version: caps.get(16).unwrap().as_str(),
            user_agent: caps.get(17).unwrap().as_str(),
            ssl_cipher: caps.get(18).unwrap().as_str(),
            ssl_protocol: caps.get(19).unwrap().as_str(),
        }
    }
}

fn main() {
    let stdin = stdin();
    let stdout = stdout();

    let stdin = stdin.lock();
    let stdout = stdout.lock();
    let mut stdout = BufWriter::new(stdout);

    let parser = Parser::new();
    for line in stdin.lines() {
        let line = line.unwrap();
        let json = parser.parse(&line);
        let string = serde_json::to_string(&json).unwrap();
        writeln!(stdout, "{}", string).unwrap();
    }
}

#[test]
fn test_parser() {
    let parser = Parser::new();
    let t = |input, expected| {
        assert_eq!(
            serde_json::to_string(&parser.parse(input)).unwrap(),
            expected
        )
    };

    t(
        r#"2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000073 0.001048 0.000057 200 200 0 29 "GET http://www.example.com:80/ HTTP/1.1" "curl/7.38.0" - -"#,
        r#"{"time":"2015-05-13T23:39:43.945958Z","elb":"my-loadbalancer","client_ip":"192.168.131.39","client_port":"2817","backend_ip":"10.0.0.1","backend_port":"80","request_processing_time":"0.000073","backend_processing_time":"0.001048","response_processing_time":"0.000057","elb_status_code":"200","backend_status_code":"200","received_bytes":"0","sent_bytes":"29","http_method":"GET","url":"http://www.example.com:80/","http_version":"HTTP/1.1","user_agent":"\"curl/7.38.0\"","ssl_cipher":"-","ssl_protocol":"-"}"#,
    );
    t(
        r#"2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000086 0.001048 0.001337 200 200 0 57 "GET https://www.example.com:443/ HTTP/1.1" "curl/7.38.0" DHE-RSA-AES128-SHA TLSv1.2"#,
        r#"{"time":"2015-05-13T23:39:43.945958Z","elb":"my-loadbalancer","client_ip":"192.168.131.39","client_port":"2817","backend_ip":"10.0.0.1","backend_port":"80","request_processing_time":"0.000086","backend_processing_time":"0.001048","response_processing_time":"0.001337","elb_status_code":"200","backend_status_code":"200","received_bytes":"0","sent_bytes":"57","http_method":"GET","url":"https://www.example.com:443/","http_version":"HTTP/1.1","user_agent":"\"curl/7.38.0\"","ssl_cipher":"DHE-RSA-AES128-SHA","ssl_protocol":"TLSv1.2"}"#,
    );
    t(
        r#"2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.001069 0.000028 0.000041 - - 82 305 "- - - " "-" - -"#,
        r#"{"time":"2015-05-13T23:39:43.945958Z","elb":"my-loadbalancer","client_ip":"192.168.131.39","client_port":"2817","backend_ip":"10.0.0.1","backend_port":"80","request_processing_time":"0.001069","backend_processing_time":"0.000028","response_processing_time":"0.000041","elb_status_code":"-","backend_status_code":"-","received_bytes":"82","sent_bytes":"305","http_method":"-","url":"-","http_version":"- ","user_agent":"\"-\"","ssl_cipher":"-","ssl_protocol":"-"}"#,
    );
    t(
        r#"2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.001065 0.000015 0.000023 - - 57 502 "- - - " "-" ECDHE-ECDSA-AES128-GCM-SHA256 TLSv1.2"#,
        r#"{"time":"2015-05-13T23:39:43.945958Z","elb":"my-loadbalancer","client_ip":"192.168.131.39","client_port":"2817","backend_ip":"10.0.0.1","backend_port":"80","request_processing_time":"0.001065","backend_processing_time":"0.000015","response_processing_time":"0.000023","elb_status_code":"-","backend_status_code":"-","received_bytes":"57","sent_bytes":"502","http_method":"-","url":"-","http_version":"- ","user_agent":"\"-\"","ssl_cipher":"ECDHE-ECDSA-AES128-GCM-SHA256","ssl_protocol":"TLSv1.2"}"#,
    );
}
