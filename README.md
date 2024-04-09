elb-log-parser
========
Simple AWS ELB log parser which parses Classic LB and ALB logs into JSONs.

```console
$ elb-log-parser

Simple AWS ELB log parser which parses Classic LB and ALB logs into JSONs.

Usage: elb-log-parser [OPTIONS] <PATH>

Arguments:
  <PATH>  Path of directory containing load balancer logs. To read from stdin, use "-"

Options:
  -t, --type <TYPE>        Type of load balancer [default: alb] [possible values: alb, classic-lb]
      --skip-parse-errors  Skip parsing errors
  -h, --help               Print help
  -V, --version            Print version
```

Usage example:

```console
$ gzcat ./alb.log.gz
h2 2022-11-01T23:50:27.908737Z app/my-alb/1234567890abcdef 123.123.123.123:65432 10.0.10.0:8080 0.000 0.004 0.000 200 200 288 131 "GET https://example.com HTTP/2.0" "Mozilla/5.0 (iPhone; CPU iPhone OS 15_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MYAPP/4.2.1 iOS/15.6.1 iPhone12,3" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:ap-northeast-2:1234567890:targetgroup/mytargetgroup/0123456789abcdef "Root=1-12345678-01234567890123456789" "example.com" "arn:aws:acm:ap-northeast-2:1234567890:certificate/abcdefgh-abcd-efgh-ijkl-0123456789" 5 2022-11-01T23:50:27.904000Z "forward" "-" "-" "10.0.10.0:8080" "200" "-" "-"
$ elb-log-parser ./alb.log.gz
{"type":"h2","time":"2022-11-01T23:50:27.908737Z","elb":"app/my-alb/1234567890abcdef","client_ip":"123.123.123.123","client_port":"65432","target_ip_port":"10.0.10.0:8080","request_processing_time":"0.000","target_processing_time":"0.004","response_processing_time":"0.000","elb_status_code":"200","target_status_code":"200","received_bytes":"288","sent_bytes":"131","http_method":"GET","url":"https://example.com","http_version":"HTTP/2.0","user_agent":"\"Mozilla/5.0 (iPhone; CPU iPhone OS 15_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MYAPP/4.2.1 iOS/15.6.1 iPhone12,3\"","ssl_cipher":"ECDHE-RSA-AES128-GCM-SHA256","ssl_protocol":"TLSv1.2","target_group_arn":"arn:aws:elasticloadbalancing:ap-northeast-2:1234567890:targetgroup/mytargetgroup/0123456789abcdef","trace_id":"Root=1-12345678-01234567890123456789","domain_name":"example.com","chosen_cert_arn":"arn:aws:acm:ap-northeast-2:1234567890:certificate/abcdefgh-abcd-efgh-ijkl-0123456789","matched_rule_priority":"5","request_creation_time":"2022-11-01T23:50:27.904000Z","actions_executed":"forward","redirect_url":"-","error_reason":"-","target_ip_port_list":"10.0.10.0:8080","target_status_code_list":"200","classification":"-","classification_reason":"-"}
```

### Installation
Using Homebrew in macOS:
```bash
brew install simnalamburt/x/elb-log-parser
```

Using Cargo:
```bash
cargo install elb-log-parser
```

&nbsp;

--------

*elb-log-parser* is primarily distributed under the terms of the [GNU Affero
General Public License v3.0] or any later version. See [COPYRIGHT] for details.

[GNU Affero General Public License v3.0]: LICENSE
[COPYRIGHT]: COPYRIGHT
