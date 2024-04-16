from datetime import datetime
import re
from ipaddress import IPv4Address
import Helpers


def get_IPv4_address(text):
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    match = re.search(pattern, text)
    if match:
        return IPv4Address(match.group(0))
    else:
        return None


def get_user_from_log(description):
    pattern = r'(user|for) (\S+)(?: \[.*\])?'
    match = re.search(pattern, description)
    if match:
        return match.group(1)
    else:
        return None


def get_message_type(description):
    if re.search(r'failed password', description, re.IGNORECASE):
        return "Invalid Password Log Entry"
    elif re.search(r'accepted', description, re.IGNORECASE):
        return "Password Accepted Log Entry"
    elif re.search(r'error', description, re.IGNORECASE):
        return "Error Log Entry"
    else:
        return "Other Log Entry"


def get_time(line):
    pattern = r'^(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})'
    match = re.search(pattern, line)
    if match:
        return datetime.strptime(match.group(1), "%b %d %H:%M:%S")
    else:
        return None


def get_host_name(line):
    pattern = r'\b\w{3} \d{1,2} \d{2}:\d{2}:\d{2} (\w+)'
    match = re.search(pattern, line)
    if match:
        return match.group(1)
    else:
        return None


def get_app_component(line):
    pattern = r'(\w+)\[\d+\]:'
    match = re.search(pattern, line)
    if match:
        return match.group(1)
    else:
        return None


def get_pid(line):
    pattern = r'\[(\d+)\]:'
    match = re.search(pattern, line)
    if match:
        return match.group(1)
    else:
        return None


def get_description(line):
    pattern = r'\[\d+\]:\s*(.*$)'
    match = re.search(pattern, line)
    if match:
        return match.group(1)
    else:
        return None

