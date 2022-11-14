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
    pub r#type: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub time: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub elb: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub client_ip: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub client_port: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub target_ip_port: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub request_processing_time: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub target_processing_time: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub response_processing_time: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub elb_status_code: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub target_status_code: &'a [u8],
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
    #[serde(serialize_with = "bytes_ser")]
    pub target_group_arn: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub trace_id: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub domain_name: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub chosen_cert_arn: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub matched_rule_priority: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub request_creation_time: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub actions_executed: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub redirect_url: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub error_reason: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub target_ip_port_list: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub target_status_code_list: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub classification: &'a [u8],
    #[serde(serialize_with = "bytes_ser")]
    pub classification_reason: &'a [u8],
}

pub struct LogParser {
    regex: Regex,
    locs: RefCell<CaptureLocations>,
}

impl LogParser {
    pub fn new() -> Self {
        // https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html#access-log-entry-format
        let regex = Regex::new(
            r#"(?x)
            ^
            (http|https|h2|grpcs|ws|wss)                            # type
            \x20
            ([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}Z)   # time
            \x20
            ([a-zA-Z0-9](?:[/a-zA-Z0-9-]*[a-zA-Z0-9])?)             # elb
            \x20
            ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})        # client ip
            :
            ([0-9]{1,5})                                            # client port
            \x20
            ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}|-)   # target ip port
            \x20
            ([0-9]+\.[0-9]+|-1)                                     # request processing time
            \x20
            ([0-9]+\.[0-9]+|-1)                                     # target processing time
            \x20
            ([0-9]+\.[0-9]+|-1)                                     # response processing time
            \x20
            ([0-9]{3}|-)                                            # elb status code
            \x20
            ([0-9]{3}|-)                                            # target status code
            \x20
            ([0-9]+)                                                # received bytes
            \x20
            ([0-9]+)                                                # sent bytes
            \x20
            "
                (-|[A-Z_]+)                                         # http method
                \x20
                ((?:[^\n\\"]|\\"|\\\\|\\x[0-9a-f]{8})*)             # URL
                \x20
                (-\x20?|HTTP/[0-9.]+)                               # http version
            "
            \x20
            ("(?:[^\n\\"]|\\"|\\\\|\\x[0-9a-f]{8})*")               # user agent
            \x20
            ([0-9A-Z-]+)                                            # ssl cipher
            \x20
            (TLSv[0-9.]+|-)                                         # ssl protocol
            \x20
            (arn:[^\x20]*|-)                                        # target_group_arn
            \x20
            "((?:[^\\"]|\\")*)"                                     # trace_id
            \x20
            "([0-9A-Za-z.\-\*]*)"                                   # domain_name
            \x20
            "(arn:(?:[^\\"]|\\")*|session-reused|-)"                # chosen_cert_arn
            \x20
            ([0-9]{1,5}|-1|-)                                       # matched_rule_priority
            \x20
            ([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}Z)   # request_creation_time
            \x20
            "([a-z-]*)"                                             # actions_executed
            \x20
            "((?:[^\n\\"]|\\"|\\\\|\\x[0-9a-f]{8})*|-)"             # redirect_url
            \x20
            "([a-zA-Z]+|-)"                                         # error_reason
            \x20
            "(
                (?:
                    [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}
                    (?:\x20[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5})*
                )
                |
                -
            )"                                                      # target_ip_port_list
            \x20
            "(
                (?:
                    [0-9]{3}
                    (?:\x20[0-9]{3})*
                )
                |
                -
            )"                                                      # target_status_code_list
            \x20
            "(Acceptable|Ambiguous|Severe|-)"                       # classification
            \x20
            "([a-zA-Z]+|-)"                                         # classification_reason
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
        self.regex
            .captures_read(&mut locs, log)
            .ok_or_else(|| ParseLogError::InvalidLogFormat(String::from_utf8_lossy(log).to_string()))?;

        let s = |i| {
            let (start, end) = locs.get(i).unwrap();
            &log[start..end]
        };

        Ok(Log {
            r#type: s(1),
            time: s(2),
            elb: s(3),
            client_ip: s(4),
            client_port: s(5),
            target_ip_port: s(6),
            request_processing_time: s(7),
            target_processing_time: s(8),
            response_processing_time: s(9),
            elb_status_code: s(10),
            target_status_code: s(11),
            received_bytes: s(12),
            sent_bytes: s(13),
            http_method: s(14),
            url: s(15),
            http_version: s(16),
            user_agent: s(17),
            ssl_cipher: s(18),
            ssl_protocol: s(19),
            target_group_arn: s(20),
            trace_id: s(21),
            domain_name: s(22),
            chosen_cert_arn: s(23),
            matched_rule_priority: s(24),
            request_creation_time: s(25),
            actions_executed: s(26),
            redirect_url: s(27),
            error_reason: s(28),
            target_ip_port_list: s(29),
            target_status_code_list: s(30),
            classification: s(31),
            classification_reason: s(32),
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
        br#"h2 2022-11-01T23:50:27.908737Z app/my-alb/1234567890abcdef 123.123.123.123:65432 10.0.10.0:8080 0.000 0.004 0.000 200 200 288 131 "GET https://example.com HTTP/2.0" "Mozilla/5.0 (iPhone; CPU iPhone OS 15_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MYAPP/4.2.1 iOS/15.6.1 iPhone12,3" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:ap-northeast-2:1234567890:targetgroup/mytargetgroup/0123456789abcdef "Root=1-12345678-01234567890123456789" "example.com" "arn:aws:acm:ap-northeast-2:1234567890:certificate/abcdefgh-abcd-efgh-ijkl-0123456789" 5 2022-11-01T23:50:27.904000Z "forward" "-" "-" "10.0.10.0:8080" "200" "-" "-"
"#,
        r#"{"type":"h2","time":"2022-11-01T23:50:27.908737Z","elb":"app/my-alb/1234567890abcdef","client_ip":"123.123.123.123","client_port":"65432","target_ip_port":"10.0.10.0:8080","request_processing_time":"0.000","target_processing_time":"0.004","response_processing_time":"0.000","elb_status_code":"200","target_status_code":"200","received_bytes":"288","sent_bytes":"131","http_method":"GET","url":"https://example.com","http_version":"HTTP/2.0","user_agent":"\"Mozilla/5.0 (iPhone; CPU iPhone OS 15_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MYAPP/4.2.1 iOS/15.6.1 iPhone12,3\"","ssl_cipher":"ECDHE-RSA-AES128-GCM-SHA256","ssl_protocol":"TLSv1.2","target_group_arn":"arn:aws:elasticloadbalancing:ap-northeast-2:1234567890:targetgroup/mytargetgroup/0123456789abcdef","trace_id":"Root=1-12345678-01234567890123456789","domain_name":"example.com","chosen_cert_arn":"arn:aws:acm:ap-northeast-2:1234567890:certificate/abcdefgh-abcd-efgh-ijkl-0123456789","matched_rule_priority":"5","request_creation_time":"2022-11-01T23:50:27.904000Z","actions_executed":"forward","redirect_url":"-","error_reason":"-","target_ip_port_list":"10.0.10.0:8080","target_status_code_list":"200","classification":"-","classification_reason":"-"}"#,
    )?;

    t(
        br#"http 2022-11-03T21:10:11.091427Z app/my-alb/1234567890abcdef 123.123.123.123:65432 - -1 -1 -1 400 - 0 272 "- http://example.com:8080- -" "-" - - - "-" "-" "-" - 2022-11-03T21:10:10.933000Z "-" "-" "-" "-" "-" "-" "-""#,
        r#"{"type":"http","time":"2022-11-03T21:10:11.091427Z","elb":"app/my-alb/1234567890abcdef","client_ip":"123.123.123.123","client_port":"65432","target_ip_port":"-","request_processing_time":"-1","target_processing_time":"-1","response_processing_time":"-1","elb_status_code":"400","target_status_code":"-","received_bytes":"0","sent_bytes":"272","http_method":"-","url":"http://example.com:8080-","http_version":"-","user_agent":"\"-\"","ssl_cipher":"-","ssl_protocol":"-","target_group_arn":"-","trace_id":"-","domain_name":"-","chosen_cert_arn":"-","matched_rule_priority":"-","request_creation_time":"2022-11-03T21:10:10.933000Z","actions_executed":"-","redirect_url":"-","error_reason":"-","target_ip_port_list":"-","target_status_code_list":"-","classification":"-","classification_reason":"-"}"#,
    )?;

    t(
        br#"h2 2022-11-03T10:05:44.872310Z app/myalb/0123456789012 123.123.123.123:54321 10.0.10.0:8080 0.000 0.003 0.000 200 200 285 131 "GET https://example.com:443/api/ HTTP/2.0" "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MYAPP/4.2.1 iOS/16.0 iPhone13,1" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:ap-northeast-2:0123456789:targetgroup/mytargetgrouop/01234567890 "Root=1-abcdefgh-abcd-efgh-ijkl-0123456789" "example.com" "session-reused" 5 2022-11-03T10:05:44.869000Z "forward" "-" "-" "10.0.10.0:8080" "200" "-" "-""#,
        r#"{"type":"h2","time":"2022-11-03T10:05:44.872310Z","elb":"app/myalb/0123456789012","client_ip":"123.123.123.123","client_port":"54321","target_ip_port":"10.0.10.0:8080","request_processing_time":"0.000","target_processing_time":"0.003","response_processing_time":"0.000","elb_status_code":"200","target_status_code":"200","received_bytes":"285","sent_bytes":"131","http_method":"GET","url":"https://example.com:443/api/","http_version":"HTTP/2.0","user_agent":"\"Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MYAPP/4.2.1 iOS/16.0 iPhone13,1\"","ssl_cipher":"ECDHE-RSA-AES128-GCM-SHA256","ssl_protocol":"TLSv1.2","target_group_arn":"arn:aws:elasticloadbalancing:ap-northeast-2:0123456789:targetgroup/mytargetgrouop/01234567890","trace_id":"Root=1-abcdefgh-abcd-efgh-ijkl-0123456789","domain_name":"example.com","chosen_cert_arn":"session-reused","matched_rule_priority":"5","request_creation_time":"2022-11-03T10:05:44.869000Z","actions_executed":"forward","redirect_url":"-","error_reason":"-","target_ip_port_list":"10.0.10.0:8080","target_status_code_list":"200","classification":"-","classification_reason":"-"}"#
    )?;

    t(
        br#"https 2022-11-02T16:16:31.662027Z app/myalb/0123456789012 123.123.123.123:54321 - -1 -1 -1 503 - 199 184 "GET https://10.100.10.100:443/ HTTP/1.1" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 - "Root=1-abcdefgh-abcd-efgh-ijkl-0123456789" "*" "arn:aws:acm:ap-northeast-2:1234567890:certificate/abcdefgh-abcd-efgh-ijkl-0123456789" 0 2022-11-02T16:16:31.661000Z "fixed-response" "-" "-" "-" "-" "-" "-""#,
        r#"{"type":"https","time":"2022-11-02T16:16:31.662027Z","elb":"app/myalb/0123456789012","client_ip":"123.123.123.123","client_port":"54321","target_ip_port":"-","request_processing_time":"-1","target_processing_time":"-1","response_processing_time":"-1","elb_status_code":"503","target_status_code":"-","received_bytes":"199","sent_bytes":"184","http_method":"GET","url":"https://10.100.10.100:443/","http_version":"HTTP/1.1","user_agent":"\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36\"","ssl_cipher":"ECDHE-RSA-AES128-GCM-SHA256","ssl_protocol":"TLSv1.2","target_group_arn":"-","trace_id":"Root=1-abcdefgh-abcd-efgh-ijkl-0123456789","domain_name":"*","chosen_cert_arn":"arn:aws:acm:ap-northeast-2:1234567890:certificate/abcdefgh-abcd-efgh-ijkl-0123456789","matched_rule_priority":"0","request_creation_time":"2022-11-02T16:16:31.661000Z","actions_executed":"fixed-response","redirect_url":"-","error_reason":"-","target_ip_port_list":"-","target_status_code_list":"-","classification":"-","classification_reason":"-"}"#
    )?;

    t(
        br#"https 2022-11-02T16:16:31.662027Z app/myalb/0123456789012 123.123.123.123:54321 - -1 -1 -1 400 - 192 272 "SSTP_DUPLEX_POST https://10.100.10.100:443/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1" "-" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 - "-" "-" "arn:aws:acm:ap-northeast-2:1234567890:certificate/abcdefgh-abcd-efgh-ijkl-0123456789" - 2022-11-02T16:16:31.661000Z "-" "-" "-" "-" "-" "-" "-""#,
        r#"{"type":"https","time":"2022-11-02T16:16:31.662027Z","elb":"app/myalb/0123456789012","client_ip":"123.123.123.123","client_port":"54321","target_ip_port":"-","request_processing_time":"-1","target_processing_time":"-1","response_processing_time":"-1","elb_status_code":"400","target_status_code":"-","received_bytes":"192","sent_bytes":"272","http_method":"SSTP_DUPLEX_POST","url":"https://10.100.10.100:443/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/","http_version":"HTTP/1.1","user_agent":"\"-\"","ssl_cipher":"ECDHE-RSA-AES128-GCM-SHA256","ssl_protocol":"TLSv1.2","target_group_arn":"-","trace_id":"-","domain_name":"-","chosen_cert_arn":"arn:aws:acm:ap-northeast-2:1234567890:certificate/abcdefgh-abcd-efgh-ijkl-0123456789","matched_rule_priority":"-","request_creation_time":"2022-11-02T16:16:31.661000Z","actions_executed":"-","redirect_url":"-","error_reason":"-","target_ip_port_list":"-","target_status_code_list":"-","classification":"-","classification_reason":"-"}"#
    )?;

    Ok(())
}
