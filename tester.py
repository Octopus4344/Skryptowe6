import datetime
import random

from Helpers import classify_entry
from SSHLogJournal import SSHLogJournal
from SSHUser import SSHUser

entry = classify_entry(
    "Dec 10 09:11:22 LabSZ sshd[24439]: error: Received disconnect from 103.99.0.122: 14: No more user authentication methods available. [preauth]")
print(entry)
print(entry.type)
print(entry.IPv4_address)
print(entry.validate())
print(entry.has_ip)
print(entry.__repr__())

print("\n--------------------------------------------------\n")

journal = SSHLogJournal()
journal.append(
    "Dec 10 06:55:46 LabSZ sshd[24200]: reverse mapping checking getaddrinfo for ns.marryaldkfaczcz.com [173.234.31.186] failed - POSSIBLE BREAK-IN ATTEMPT!")
journal.append(
    "Dec 10 09:11:22 LabSZ sshd[24439]: error: Received disconnect from 103.99.0.122: 14: No more user authentication methods available. [preauth]")
journal.append(
    "Dec 10 11:04:43 LabSZ sshd[25544]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=183.62.140.253  user=root")

print("Length of journal:")
print(len(journal))

print("\nIterating over journal:")
for entry in journal:
    print(entry)

print("\nSlicing journal:")
print(journal[:1])

print("\nChecking if entry is in journal:")
print(entry in journal)

print("\nGetting logs by IP:")
print(journal["103.99.0.122"])

print("\nGetting logs by date range:")
start_date = datetime.datetime(year=1900, month=12, day=10, hour=6, minute=55, second=43)
end_date = datetime.datetime(year=1900, month=12, day=10, hour=10, minute=4, second=43)
for entry in journal[start_date, end_date]:
    print(entry)

print("\n--------------------------------------------------\n")

objects_list = [SSHUser("user_1", datetime.datetime(year=2024, month=4, day=16, hour=12, minute=30, second=45)),
                SSHUser("user-2", datetime.datetime(year=2024, month=4, day=17, hour=12, minute=30, second=45)),
                SSHUser("user_3", datetime.datetime(year=2024, month=4, day=18, hour=12, minute=30, second=45)),
                SSHUser("User_4", datetime.datetime(year=2024, month=4, day=19, hour=12, minute=30, second=45)),
                classify_entry("blah blah blah"),
                *journal.entries]

random.shuffle(objects_list)

for entry in objects_list:
    print(f"{entry.validate()} - {entry}")
