import pytest
from datetime import datetime
from Helpers import classify_entry

sample_logs = [
    ("Dec 10 06:55:46", "Dec 10 06:55:46 LabSZ sshd[24200]: reverse mapping checking getaddrinfo for "
                        "ns.marryaldkfaczcz.com [173.234.31.186] failed - POSSIBLE BREAK-IN ATTEMPT!"),
    ("Dec 10 06:55:46", "Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186"),
    ("Dec 10 06:55:46", "Dec 10 06:55:46 LabSZ sshd[24200]: input_userauth_request: invalid user webmaster [preauth]"),
    ("Dec 10 06:55:46", "Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:auth): check pass; user unknown")
]


@pytest.mark.parametrize("expected_time, log_content", sample_logs)
def test_extract_time(expected_time, log_content):
    entry = classify_entry(log_content)
    assert entry.time == datetime.strptime(expected_time, "%b %d %H:%M:%S")
