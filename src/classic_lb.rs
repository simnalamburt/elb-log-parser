use std::cell::RefCell;

use anyhow::Result;
use regex::bytes::{CaptureLocations, Regex};
use serde::{ser, Serialize, Serializer};

use crate::parse::{LBLogParser, ParseLogError};

fn bytes_ser<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let str = std::str::from_utf8(bytes)
        .map_err(|_| ser::Error::custom("log contains invalid UTF-8 characters"))?;
    serializer.serialize_str(str)
}

#[derive(Serialize)]
pub struct Log<'a> {
    #[serde(serialize_with = "bytes_ser")]
    pub time: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub elb: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub client_ip: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub client_port: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub backend_ip_port: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub request_processing_time: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub backend_processing_time: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub response_processing_time: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub elb_status_code: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub backend_status_code: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub received_bytes: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub sent_bytes: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub http_method: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub url: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub http_version: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub user_agent: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub ssl_cipher: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub ssl_protocol: &'a [u8],
}

pub struct LogParser {
    regex: Regex,
    locs: RefCell<CaptureLocations>,
}

impl LogParser {
    pub fn new() -> Self {
        // https://docs.aws.amazon.com/en_us/elasticloadbalancing/latest/classic/access-log-collection.html#access-log-entry-syntax
        let regex = Regex::new(
            r#"(?x)
            ^
            ([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}Z)   # time
            \x20
            ([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)          # elb
            \x20
            ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})    # client ip
            :
            ([0-9]{1,5})                                        # client port
            \x20
            ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}|-)   # backend ip port
            \x20
            ([0-9]+\.[0-9]+|-1)                                 # request processing time
            \x20
            ([0-9]+\.[0-9]+|-1)                                 # backend processing time
            \x20
            ([0-9]+\.[0-9]+|-1)                                 # response processing time
            \x20
            ([0-9]{3}|-)                                        # elb status code
            \x20
            ([0-9]{1,3}|-)                                      # backend status code
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
            "((?:[^\n\\"]|\\"|\\\\|\\x[0-9a-f]{8})*)"           # user agent
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
}

impl LBLogParser for LogParser {
    type Log<'input> = self::Log<'input>;

    fn parse<'input>(&self, log: &'input [u8]) -> Result<Log<'input>, ParseLogError> {
        let mut locs = self.locs.borrow_mut();
        self.regex.captures_read(&mut locs, log).ok_or_else(|| {
            ParseLogError::InvalidLogFormat(String::from_utf8_lossy(log).to_string())
        })?;

        let s = |i| {
            let (start, end) = locs.get(i).unwrap();
            &log[start..end]
        };

        Ok(Log {
            time: s(1),
            elb: s(2),
            client_ip: s(3),
            client_port: s(4),
            backend_ip_port: s(5),
            request_processing_time: s(6),
            backend_processing_time: s(7),
            response_processing_time: s(8),
            elb_status_code: s(9),
            backend_status_code: s(10),
            received_bytes: s(11),
            sent_bytes: s(12),
            http_method: s(13),
            url: s(14),
            http_version: s(15),
            user_agent: s(16),
            ssl_cipher: s(17),
            ssl_protocol: s(18),
        })
    }
}

#[test]
fn test_log_parser() -> Result<()> {
    let parser = LogParser::new();
    let t = |input, expected| -> Result<()> {
        assert_eq!(serde_json::to_string(&mut parser.parse(input)?)?, expected);
        Ok(())
    };

    t(
        br#"2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000073 0.001048 0.000057 200 200 0 29 "GET http://www.example.com:80/ HTTP/1.1" "curl/7.38.0" - -
"#,
        r#"{"time":"2015-05-13T23:39:43.945958Z","elb":"my-loadbalancer","client_ip":"192.168.131.39","client_port":"2817","backend_ip_port":"10.0.0.1:80","request_processing_time":"0.000073","backend_processing_time":"0.001048","response_processing_time":"0.000057","elb_status_code":"200","backend_status_code":"200","received_bytes":"0","sent_bytes":"29","http_method":"GET","url":"http://www.example.com:80/","http_version":"HTTP/1.1","user_agent":"curl/7.38.0","ssl_cipher":"-","ssl_protocol":"-"}"#,
    )?;
    t(
        br#"2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000086 0.001048 0.001337 200 200 0 57 "GET https://www.example.com:443/ HTTP/1.1" "curl/7.38.0" DHE-RSA-AES128-SHA TLSv1.2
"#,
        r#"{"time":"2015-05-13T23:39:43.945958Z","elb":"my-loadbalancer","client_ip":"192.168.131.39","client_port":"2817","backend_ip_port":"10.0.0.1:80","request_processing_time":"0.000086","backend_processing_time":"0.001048","response_processing_time":"0.001337","elb_status_code":"200","backend_status_code":"200","received_bytes":"0","sent_bytes":"57","http_method":"GET","url":"https://www.example.com:443/","http_version":"HTTP/1.1","user_agent":"curl/7.38.0","ssl_cipher":"DHE-RSA-AES128-SHA","ssl_protocol":"TLSv1.2"}"#,
    )?;
    t(
        br#"2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.001069 0.000028 0.000041 - - 82 305 "- - - " "-" - -
"#,
        r#"{"time":"2015-05-13T23:39:43.945958Z","elb":"my-loadbalancer","client_ip":"192.168.131.39","client_port":"2817","backend_ip_port":"10.0.0.1:80","request_processing_time":"0.001069","backend_processing_time":"0.000028","response_processing_time":"0.000041","elb_status_code":"-","backend_status_code":"-","received_bytes":"82","sent_bytes":"305","http_method":"-","url":"-","http_version":"- ","user_agent":"-","ssl_cipher":"-","ssl_protocol":"-"}"#,
    )?;
    t(
        br#"2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.001065 0.000015 0.000023 - - 57 502 "- - - " "-" ECDHE-ECDSA-AES128-GCM-SHA256 TLSv1.2
"#,
        r#"{"time":"2015-05-13T23:39:43.945958Z","elb":"my-loadbalancer","client_ip":"192.168.131.39","client_port":"2817","backend_ip_port":"10.0.0.1:80","request_processing_time":"0.001065","backend_processing_time":"0.000015","response_processing_time":"0.000023","elb_status_code":"-","backend_status_code":"-","received_bytes":"57","sent_bytes":"502","http_method":"-","url":"-","http_version":"- ","user_agent":"-","ssl_cipher":"ECDHE-ECDSA-AES128-GCM-SHA256","ssl_protocol":"TLSv1.2"}"#,
    )?;
    t(
        br#"2015-03-27T07:06:41.177907Z my-loadbalancer 192.168.131.39:2817 - -1 -1 -1 503 0 0 0 "GET https://www.example.com:443/ HTTP/1.1" "curl/7.38.0" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2
"#,
        r#"{"time":"2015-03-27T07:06:41.177907Z","elb":"my-loadbalancer","client_ip":"192.168.131.39","client_port":"2817","backend_ip_port":"-","request_processing_time":"-1","backend_processing_time":"-1","response_processing_time":"-1","elb_status_code":"503","backend_status_code":"0","received_bytes":"0","sent_bytes":"0","http_method":"GET","url":"https://www.example.com:443/","http_version":"HTTP/1.1","user_agent":"curl/7.38.0","ssl_cipher":"ECDHE-RSA-AES128-GCM-SHA256","ssl_protocol":"TLSv1.2"}"#,
    )?;

    Ok(())
}
