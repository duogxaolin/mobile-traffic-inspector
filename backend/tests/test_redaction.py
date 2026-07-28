from app.redaction import REDACTED, redact_body, redact_headers, redact_query


def test_sensitive_headers_and_queries_are_masked_but_duplicates_preserved():
    headers = [["Cookie", "sid=secret"], ["X-Test", "one"], ["X-Test", "two"]]
    assert redact_headers(headers) == [["Cookie", REDACTED], ["X-Test", "one"], ["X-Test", "two"]]
    assert redact_query([["token", "abc"], ["q", "hello"]])[0][1] == REDACTED


def test_json_and_binary_body_redaction():
    body, view = redact_body(b'{"name":"Ada","token":"do-not-show"}', "application/json")
    assert view == "json"
    assert b"do-not-show" not in body
    body, view = redact_body(b"\x00\x01secret", "image/png")
    assert view == "binary-redacted"
    assert b"secret" not in body
