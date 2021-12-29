use std::io::Write;
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

fn main() {
    println!("Hello, world!");
}

#[test]
fn test_regex() {
    // https://docs.aws.amazon.com/en_us/elasticloadbalancing/latest/classic/access-log-collection.html#access-log-entry-syntax
    let re = Regex::new(r#"(?xm)
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
    "#).unwrap();

    let input = r#"2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000073 0.001048 0.000057 200 200 0 29 "GET http://www.example.com:80/ HTTP/1.1" "curl/7.38.0" - -
2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000086 0.001048 0.001337 200 200 0 57 "GET https://www.example.com:443/ HTTP/1.1" "curl/7.38.0" DHE-RSA-AES128-SHA TLSv1.2
2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.001069 0.000028 0.000041 - - 82 305 "- - - " "-" - -
2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.001065 0.000015 0.000023 - - 57 502 "- - - " "-" ECDHE-ECDSA-AES128-GCM-SHA256 TLSv1.2
"#;

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    for caps in re.captures_iter(input) {
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

        let json = serde_json::to_string(&log).unwrap();
        writeln!(handle, "{}", json).unwrap();
    }
}
