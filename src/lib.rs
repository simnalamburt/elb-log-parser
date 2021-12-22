use lalrpop_util::lalrpop_mod;

mod lex;

lalrpop_mod!(pub classic_lb);

// TODO:
// - str 보다 유용한 타입 사용
// - V1 V2 둘다 지원
// - 모든 필드 지원
// - Implement Classic LB v1 and v2 log formats
// - 모든 필드에 문서 추가
pub struct ClassicLBLog<'input> {
    /// > The time when the load balancer received the request from the client, in
    /// > ISO 8601 format.
    ///
    /// Instead of full ISO 8601 format, only "YYYY-MM-DDTHH:MM:SS.xxxxxxZ" format
    /// is supported.
    ///
    /// #### Reference
    /// - https://datatracker.ietf.org/doc/html/rfc3339
    pub timestamp: &'input str,

    /// > The name of the load balancer.
    /// >
    /// > This name must be unique within your set of load balancers for the region,
    /// > must have a maximum of 32 characters, must contain only alphanumeric
    /// > characters or hyphens, and cannot begin or end with a hyphen.
    ///
    /// #### Reference
    /// - https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_CreateLoadBalancer.html#API_CreateLoadBalancer_RequestParameters
    pub elb: &'input str,

    /// > The IP address and port of the requesting client.
    pub client: &'input str,

    /// > The IP address and port of the registered instance that processed this request.
    /// >
    /// > If the load balancer can't send the request to a registered instance, or if the instance
    /// > closes the connection before a response can be sent, this value is set to -.
    /// >
    /// > This value can also be set to - if the registered instance does not respond before the
    /// > idle timeout.
    pub backend: &'input str,

    pub request_processing_time: &'input str,
    pub backend_processing_time: &'input str,
    pub response_processing_time: &'input str,
    pub elb_status_code: &'input str,
    pub backend_status_code: &'input str,
    pub received_bytes: &'input str,
    pub sent_bytes: &'input str,

    // TODO
    //pub request: &'input str,
    //pub user_agent: &'input str,
    //pub ssl_cipher: &'input str,
    //pub ssl_protocol: &'input str,
}

#[cfg(test)]
mod tests {
    use lalrpop_util::ParseError;
    use crate::classic_lb::TestParser;
    use crate::lex::{Tok, Lexer};

    type TestResult = Result<(), ParseError<usize, Tok<'static>, &'static str>>;

    fn t(input: &'static str) -> TestResult {
        TestParser::new().parse(input, Lexer::new(input))
    }

    fn e(input: &'static str) {
        assert!(TestParser::new().parse(input, Lexer::new(input)).is_err());
    }

    #[test]
    fn test_timestamp() -> TestResult {
        t("Timestamp 2021-11-22T01:58:01.532018Z")?;

        Ok(())
    }

    #[test]
    fn test_name() -> TestResult {
        t("Name a")?;
        t("Name ELB-NAME")?;

        e("Name ");
        e("Name -");
        e("Name a-");
        e("Name -a");
        e("Name ELB_NAME");
        e("Name asd*asd");
        e("Name asd가asd");
        e("Name TOO-LONG-ELB-NAME-TOO-LONG-ELB-NAME-TOO-LONG-ELB-NAME-TOO-LONG-ELB-NAME-TOO-LONG-ELB-NAME");

        Ok(())
    }

    #[test]
    fn test_ip_and_port() -> TestResult {
        t("IPAndPort 127.0.0.1:1234")?;
        t("IPAndPort 1.1.1.1:80")?;
        t("IPAndPort 255.255.255.255:65432")?;

        e("IPAndPort -");
        e("IPAndPort 127.0.0.1");
        e("IPAndPort 127.0.0.1:");
        e("IPAndPort 255.255.255.2555:123");
        e("IPAndPort 255.255.255:123");

        t("NullableIPAndPort 127.0.0.1:1234")?;
        t("NullableIPAndPort -")?;

        Ok(())
    }

    #[test]
    fn test_int() -> TestResult {
        t("Int 1")?;
        t("Int 123")?;
        t("Int 00000000")?;

        e("Int ");
        e("Int .");
        e("Int -");
        e("Int -.");
        e("Int -1");
        e("Int -0");
        e("Int 0.00100");
        e("Int -0123.450");
        e("Int .00100");
        e("Int 00100.");

        Ok(())
    }

    #[test]
    fn test_processing_time() -> TestResult {
        t("ProcessingTime 1")?;
        t("ProcessingTime 123")?;
        t("ProcessingTime 0.00100")?;
        t("ProcessingTime 00000000")?;
        t("ProcessingTime -1")?;

        e("ProcessingTime -0123.450");
        e("ProcessingTime -0");
        e("ProcessingTime ");
        e("ProcessingTime .");
        e("ProcessingTime -");
        e("ProcessingTime -.");
        e("ProcessingTime .00100");
        e("ProcessingTime 00100.");

        Ok(())
    }
}
