from datetime import datetime
from ipaddress import IPv4Address

import pytest

from Helpers import classify_entry

sample_logs = [
    "Dec 10 06:55:46 LabSZ sshd[24200]: reverse mapping checking getaddrinfo for ns.marryaldkfaczcz.com [173.234.31.186] failed - POSSIBLE BREAK-IN ATTEMPT!",
    "Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186",
    "Dec 10 06:55:46 LabSZ sshd[24200]: input_userauth_request: invalid user webmaster [preauth]",
    "Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:auth): check pass; user unknown",
    "Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from1 73.234.31.186 port 38926 ssh2",
    "Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from1 666.777.88.213 port 38926 ssh2"
]


@pytest.mark.parametrize(
    "log_content, expected_time", [
        (sample_logs[0], "Dec 10 06:55:46"),
        (sample_logs[1], "Dec 10 06:55:46"),
        (sample_logs[2], "Dec 10 06:55:46"),
        (sample_logs[3], "Dec 10 06:55:46"),
        (sample_logs[4], "Dec 10 06:55:48"),
        (sample_logs[5], "Dec 10 06:55:48")
    ]
)
def test_extract_time(log_content, expected_time):
    entry = classify_entry(log_content)
    assert entry.time == datetime.strptime(expected_time, "%b %d %H:%M:%S")


@pytest.mark.parametrize(
    "log_content, expected_ip", [
        (sample_logs[0], IPv4Address("173.234.31.186")),
        (sample_logs[1], IPv4Address("173.234.31.186")),
        (sample_logs[2], None),
        (sample_logs[3], None),
        (sample_logs[4], IPv4Address("73.234.31.186")),
        (sample_logs[5], None)
    ]
)
def test_IPv4_extraction(log_content, expected_ip):
    entry = classify_entry(log_content)
    assert entry.IPv4_address == expected_ip


sample_logs_2 = [
    "Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from1 73.234.31.186 port 38926 ssh2",
    "Dec 10 09:32:20 LabSZ sshd[24680]: Accepted password for fztu from 119.137.62.142 port 49116 ssh2",
    "Dec 10 11:03:40 LabSZ sshd[25448]: error: Received disconnect from 103.99.0.122: 14: No more user authentication methods available. [preauth]",
    "Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186",
]


@pytest.mark.parametrize(
    "log_content, expected_type", [
        (sample_logs_2[0], "Invalid Password Log Entry"),
        (sample_logs_2[1], "Password Accepted Log Entry"),
        (sample_logs_2[2], "Error Log Entry"),
        (sample_logs_2[3], "Other Log Entry")
    ]
)
def test_append_type(log_content, expected_type):
    entry = classify_entry(log_content)
    assert entry.type == expected_type
