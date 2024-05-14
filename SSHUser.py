import datetime
import re


class SSHUser:
    def __init__(self, username: str, last_login_date: datetime.datetime) -> None:
        self.username = username
        self.last_login_date = last_login_date

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(username={self.username}, last_login_date={self.last_login_date})"

    def validate(self) -> bool:
        pattern: str = r'^[a-z_][a-z0-9_-]{0,31}$'
        return re.match(pattern, self.username) is not None
