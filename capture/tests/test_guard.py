from guard import destination_allowed


def test_guard_rejects_private_loopback_metadata_and_accepts_explicit_override():
    assert destination_allowed("127.0.0.1", 443) is False
    assert destination_allowed("169.254.169.254", 80) is False
    assert destination_allowed("10.0.0.4", 443) is False
    assert destination_allowed("10.0.0.4", 443, {"10.0.0.4"}) is True
