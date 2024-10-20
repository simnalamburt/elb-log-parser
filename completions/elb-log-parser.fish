complete -c elb-log-parser -s t -l type -d 'Type of load balancer' -r -f -a "{alb\t'',classic-lb\t''}"
complete -c elb-log-parser -l skip-parse-errors -d 'Skip parsing errors'
complete -c elb-log-parser -s h -l help -d 'Print help'
complete -c elb-log-parser -s V -l version -d 'Print version'
