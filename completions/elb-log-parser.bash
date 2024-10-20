_elb-log-parser() {
    local i cur prev opts cmd
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    cmd=""
    opts=""

    for i in ${COMP_WORDS[@]}
    do
        case "${cmd},${i}" in
            ",$1")
                cmd="elb__log__parser"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        elb__log__parser)
            opts="-t -h -V --type --skip-parse-errors --help --version <PATH>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --type)
                    COMPREPLY=($(compgen -W "alb classic-lb" -- "${cur}"))
                    return 0
                    ;;
                -t)
                    COMPREPLY=($(compgen -W "alb classic-lb" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _elb-log-parser -o nosort -o bashdefault -o default elb-log-parser
else
    complete -F _elb-log-parser -o bashdefault -o default elb-log-parser
fi
