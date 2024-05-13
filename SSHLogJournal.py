from datetime import datetime
from ipaddress import IPv4Address
from typing import List, Union, Iterator

from Helpers import classify_entry


class SSHLogJournal:
    def __init__(self) -> None:
        self.entries: List = []

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator:
        return iter(self.entries)

    def __contains__(self, item: object) -> bool:
        return item in self.entries

    def __getitem__(self, key: Union) -> list:
        if isinstance(key, slice):
            return self.entries[key]
        elif isinstance(key, int):
            return self.entries[key]
        elif isinstance(key, str):
            return self.get_logs_by_ip(key)
        elif isinstance(key, tuple) and len(key) == 2 and all(isinstance(item, datetime) for item in key):
            start_date: datetime
            end_date: datetime
            start_date, end_date = key
            return self.get_logs_by_daterange(start_date, end_date)
        else:
            raise TypeError("Unsupported key type")

    def append(self, entry_text: str) -> None:
        entry = classify_entry(entry_text)
        if entry and entry.validate():
            self.entries.append(entry)

    def get_logs_by_ip(self, ip_address: str) -> List:
        return [entry for entry in self.entries if entry.IPv4_address == IPv4Address(ip_address)]

    def get_logs_by_daterange(self, start_date: datetime, end_date: datetime) -> List:
        return [entry for entry in self.entries if start_date <= entry.time <= end_date]
