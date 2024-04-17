import abc
from datetime import datetime

import Helpers


class SSHLogEntry(metaclass=abc.ABCMeta):

    def __init__(self, time: datetime, text: str, PID: int, hostname: str = None):
        self.time = time
        self.hostname = hostname
        self.__text = text
        self.PID = PID

    def __str__(self):
        return f"Time: {self.time}, Hostname: {self.hostname}, Text: {self.__text}, PID: {self.PID}"

    @property
    def IPv4_address(self):
        return Helpers.get_IPv4_address(self.__text)

    @abc.abstractmethod
    def validate(self):
        pass

    def get_text(self):
        return self.__text


class InvalidPasswordLogEntry(SSHLogEntry):
    def __init__(self, time: datetime, text: str, PID: int, hostname: str = None):
        super().__init__(time, text, PID, hostname)
        self.type = 'Invalid Password Log Entry'

    def validate(self):
        return self.type == Helpers.get_message_type(self.get_text())


class PasswordAcceptedLogEntry(SSHLogEntry):
    def __init__(self, time: datetime, text: str, PID: int, hostname: str = None):
        super().__init__(time, text, PID, hostname)
        self.type = 'Password Accepted Log Entry'

    def validate(self):
        return self.type == Helpers.get_message_type(self.get_text())


class ErrorLogEntry(SSHLogEntry):
    def __init__(self, time: datetime, text: str, PID: int, hostname: str = None):
        super().__init__(time, text, PID, hostname)
        self.type = 'Error Log Entry'

    def validate(self):
        return self.type == Helpers.get_message_type(self.get_text())


class OtherLogEntry(SSHLogEntry):
    def __init__(self, time: datetime, text: str, PID: int, hostname: str = None):
        super().__init__(time, text, PID, hostname)
        self.type = 'Other Log Entry'

    def validate(self):
        return True


def classify_entry(entry):
    log_type = Helpers.get_message_type(entry)
    time = Helpers.get_time(entry)
    hostname = Helpers.get_host_name(entry)
    PID = Helpers.get_pid(entry)
    match log_type:
        case 'Invalid Password Log Entry':
            return InvalidPasswordLogEntry(time, entry, PID, hostname)
        case 'Password Accepted Log Entry':
            return PasswordAcceptedLogEntry(time, entry, PID, hostname)
        case 'Error Log Entry':
            return ErrorLogEntry(time, entry, PID, hostname)
        case 'Other Log Entry':
            return OtherLogEntry(time, entry, PID, hostname)
    return None
