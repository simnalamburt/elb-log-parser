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
  -t, --type <TYPE>  Type of load balancer [default: alb] [possible values: alb, classic-lb]
  -h, --help         Print help
  -V, --version      Print version
```

&nbsp;

--------

*elb-log-parser* is primarily distributed under the terms of the [GNU Affero
General Public License v3.0] or any later version. See [COPYRIGHT] for details.

[GNU Affero General Public License v3.0]: LICENSE
[COPYRIGHT]: COPYRIGHT
