use std::cell::RefCell;
use std::io::{stdin, stdout, BufRead, BufWriter, Write};

use anyhow::Result;
use regex::bytes::{CaptureLocations, Regex};
use serde::{ser, Serialize, Serializer};
use serde_json::to_writer;
use thiserror::Error;

#[derive(Serialize)]
struct Log<'a> {
    #[serde(serialize_with = "bytes_ser")]
    time: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    elb: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    client_ip: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    client_port: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    backend_ip: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    backend_port: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    request_processing_time: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    backend_processing_time: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    response_processing_time: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    elb_status_code: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    backend_status_code: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    received_bytes: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    sent_bytes: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    http_method: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    url: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    http_version: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    user_agent: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    ssl_cipher: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    ssl_protocol: &'a [u8],
}

fn bytes_ser<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let str = std::str::from_utf8(bytes)
        .map_err(|_| ser::Error::custom("log contains invalid UTF-8 characters"))?;
    serializer.serialize_str(str)
}

#[derive(Error, Debug)]
enum ParseLogError {
    #[error("Invalid log line: {0:?}")]
    InvalidLogFormat(Vec<u8>),
}

struct Parser {
    regex: Regex,
    locs: RefCell<CaptureLocations>,
}

impl Parser {
    fn new() -> Self {
        // https://docs.aws.amazon.com/en_us/elasticloadbalancing/latest/classic/access-log-collection.html#access-log-entry-syntax
        let regex = Regex::new(
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
            \x0A?
            $
        "#,
        )
        .unwrap();
        let locs = RefCell::new(regex.capture_locations());

        Self { regex, locs }
    }

    fn parse<'input>(&self, log: &'input [u8]) -> Result<Log<'input>, ParseLogError> {
        let mut locs = self.locs.borrow_mut();
        self.regex
            .captures_read(&mut locs, log)
            .ok_or_else(|| ParseLogError::InvalidLogFormat(log.to_owned()))?;

        let s = |i| {
            let (start, end) = locs.get(i).unwrap();
            &log[start..end]
        };

        Ok(Log {
            time: s(1),
            elb: s(2),
            client_ip: s(3),
            client_port: s(4),
            backend_ip: s(5),
            backend_port: s(6),
            request_processing_time: s(7),
            backend_processing_time: s(8),
            response_processing_time: s(9),
            elb_status_code: s(10),
            backend_status_code: s(11),
            received_bytes: s(12),
            sent_bytes: s(13),
            http_method: s(14),
            url: s(15),
            http_version: s(16),
            user_agent: s(17),
            ssl_cipher: s(18),
            ssl_protocol: s(19),
        })
    }
}

fn main() -> Result<()> {
    let stdin = stdin();
    let mut stdin = stdin.lock();

    let mut buffer = Vec::new();
    let parser = Parser::new();

    let stdout = stdout();
    let stdout = stdout.lock();
    let mut stdout = BufWriter::new(stdout);

    while stdin.read_until(b'\n', &mut buffer)? > 0 {
        let log = parser.parse(&buffer)?;
        to_writer(&mut stdout, &log)?;
        stdout.write(b"\n")?;
        buffer.clear();
    }

    Ok(())
}

#[test]
fn test_parser() -> Result<()> {
    let parser = Parser::new();
    let t = |input, expected| -> Result<()> {
        assert_eq!(serde_json::to_string(&mut parser.parse(input)?)?, expected);
        Ok(())
    };

    t(
        br#"2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000073 0.001048 0.000057 200 200 0 29 "GET http://www.example.com:80/ HTTP/1.1" "curl/7.38.0" - -
"#,
        r#"{"time":"2015-05-13T23:39:43.945958Z","elb":"my-loadbalancer","client_ip":"192.168.131.39","client_port":"2817","backend_ip":"10.0.0.1","backend_port":"80","request_processing_time":"0.000073","backend_processing_time":"0.001048","response_processing_time":"0.000057","elb_status_code":"200","backend_status_code":"200","received_bytes":"0","sent_bytes":"29","http_method":"GET","url":"http://www.example.com:80/","http_version":"HTTP/1.1","user_agent":"\"curl/7.38.0\"","ssl_cipher":"-","ssl_protocol":"-"}"#,
    )?;
    t(
        br#"2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000086 0.001048 0.001337 200 200 0 57 "GET https://www.example.com:443/ HTTP/1.1" "curl/7.38.0" DHE-RSA-AES128-SHA TLSv1.2
"#,
        r#"{"time":"2015-05-13T23:39:43.945958Z","elb":"my-loadbalancer","client_ip":"192.168.131.39","client_port":"2817","backend_ip":"10.0.0.1","backend_port":"80","request_processing_time":"0.000086","backend_processing_time":"0.001048","response_processing_time":"0.001337","elb_status_code":"200","backend_status_code":"200","received_bytes":"0","sent_bytes":"57","http_method":"GET","url":"https://www.example.com:443/","http_version":"HTTP/1.1","user_agent":"\"curl/7.38.0\"","ssl_cipher":"DHE-RSA-AES128-SHA","ssl_protocol":"TLSv1.2"}"#,
    )?;
    t(
        br#"2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.001069 0.000028 0.000041 - - 82 305 "- - - " "-" - -
"#,
        r#"{"time":"2015-05-13T23:39:43.945958Z","elb":"my-loadbalancer","client_ip":"192.168.131.39","client_port":"2817","backend_ip":"10.0.0.1","backend_port":"80","request_processing_time":"0.001069","backend_processing_time":"0.000028","response_processing_time":"0.000041","elb_status_code":"-","backend_status_code":"-","received_bytes":"82","sent_bytes":"305","http_method":"-","url":"-","http_version":"- ","user_agent":"\"-\"","ssl_cipher":"-","ssl_protocol":"-"}"#,
    )?;
    t(
        br#"2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.001065 0.000015 0.000023 - - 57 502 "- - - " "-" ECDHE-ECDSA-AES128-GCM-SHA256 TLSv1.2
"#,
        r#"{"time":"2015-05-13T23:39:43.945958Z","elb":"my-loadbalancer","client_ip":"192.168.131.39","client_port":"2817","backend_ip":"10.0.0.1","backend_port":"80","request_processing_time":"0.001065","backend_processing_time":"0.000015","response_processing_time":"0.000023","elb_status_code":"-","backend_status_code":"-","received_bytes":"57","sent_bytes":"502","http_method":"-","url":"-","http_version":"- ","user_agent":"\"-\"","ssl_cipher":"ECDHE-ECDSA-AES128-GCM-SHA256","ssl_protocol":"TLSv1.2"}"#,
    )?;

    Ok(())
}
