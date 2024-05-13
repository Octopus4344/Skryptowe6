import abc
from datetime import datetime
from typing import Optional, Tuple

import Helpers


class SSHLogEntry(metaclass=abc.ABCMeta):

    def __init__(self, time: datetime, text: str, PID: int, hostname: Optional[str] = None):
        self.time = time
        self.hostname = hostname
        self.__text = text
        self.PID = PID

    def __str__(self):
        return f"Time: {self.time}, Hostname: {self.hostname}, Text: {self.__text}, PID: {self.PID}"

    def __repr__(self):
        return f"{self.__class__.__name__}(time={self.time}, hostname={self.hostname}, text={self.__text}, PID={self.PID}, ipv4={self.IPv4_address})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SSHLogEntry):
            return False
        return (self.time, self.__text, self.PID, self.hostname, self.IPv4_address) == (
            other.time, other.__text, other.PID, other.hostname, other.IPv4_address)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SSHLogEntry):
            raise ValueError("Comparison with non-SSHLogEntry object")
        return self.time < other.time

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, SSHLogEntry):
            raise ValueError("Comparison with non-SSHLogEntry object")
        return self.time > other.time

    @property
    def IPv4_address(self) -> Optional[str]:
        return Helpers.get_IPv4_address(self.__text)

    @property
    def has_ip(self) -> bool:
        return self.IPv4_address is not None

    @abc.abstractmethod
    def validate(self) -> bool:
        pass

    def get_text(self) -> str:
        return self.__text


class InvalidPasswordLogEntry(SSHLogEntry):
    def __init__(self, time: datetime, text: str, PID: int, username: str, hostname: Optional[str] = None):
        super().__init__(time, text, PID, hostname)
        self.type: str = 'Invalid Password Log Entry'

    def validate(self) -> bool:
        return self.type == Helpers.get_message_type(self.get_text())


class PasswordAcceptedLogEntry(SSHLogEntry):
    def __init__(self, time: datetime, text: str, PID: int, username: str, hostname: Optional[str] = None):
        super().__init__(time, text, PID, hostname)
        self.type: str = 'Password Accepted Log Entry'

    def validate(self) -> bool:
        return self.type == Helpers.get_message_type(self.get_text())


class ErrorLogEntry(SSHLogEntry):
    def __init__(self, time: datetime, text: str, PID: int, hostname: Optional[str] = None):
        super().__init__(time, text, PID, hostname)
        self.type: str = 'Error Log Entry'

    def validate(self) -> bool:
        return self.type == Helpers.get_message_type(self.get_text())


class OtherLogEntry(SSHLogEntry):
    def __init__(self, time: datetime, text: str, PID: int, hostname: Optional[str] = None):
        super().__init__(time, text, PID, hostname)
        self.type: str = 'Other Log Entry'

    def validate(self) -> bool:
        return True


