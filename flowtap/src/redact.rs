pub fn redact_http_headers(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut in_headers = true;
    for line in input.split_inclusive('\n') {
        let (body, ending) = if let Some(body) = line.strip_suffix("\r\n") {
            (body, "\r\n")
        } else if let Some(body) = line.strip_suffix('\n') {
            (body, "\n")
        } else {
            (line, "")
        };

        if body.is_empty() {
            in_headers = false;
        }
        if !in_headers {
            output.push_str(body);
            output.push_str(ending);
            continue;
        }

        let Some(colon) = body.find(':') else {
            output.push_str(body);
            output.push_str(ending);
            continue;
        };
        let name = body[..colon].trim();
        let sensitive = [
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
        ]
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate));

        if sensitive {
            output.push_str(&body[..=colon]);
            output.push_str(" [REDACTED]");
        } else {
            output.push_str(body);
        }
        output.push_str(ending);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::redact_http_headers;

    #[test]
    fn redacts_selected_headers_case_insensitively() {
        let input = concat!(
            "GET / HTTP/1.1\r\n",
            "Host: example.com\r\n",
            "Authorization: Bearer secret\r\n",
            "cookie: sid=secret\r\n",
            "\r\n"
        );
        let output = redact_http_headers(input);
        assert!(output.contains("Host: example.com\r\n"));
        assert!(output.contains("Authorization: [REDACTED]\r\n"));
        assert!(output.contains("cookie: [REDACTED]\r\n"));
        assert!(!output.contains("secret"));
    }

    #[test]
    fn redacts_last_header_without_newline() {
        assert_eq!(
            redact_http_headers("Set-Cookie: sid=secret"),
            "Set-Cookie: [REDACTED]"
        );
    }

    #[test]
    fn does_not_modify_message_body() {
        let input = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nCookie: body";
        assert_eq!(redact_http_headers(input), input);
    }
}
