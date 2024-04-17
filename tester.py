import datetime

import SSHLogEntry
import SSHLogJournal

entry = SSHLogEntry.classify_entry(
    "Dec 10 09:11:22 LabSZ sshd[24439]: error: Received disconnect from 103.99.0.122: 14: No more user authentication methods available. [preauth]")
print(entry)
print(entry.type)
print(entry.IPv4_address)
print(entry.validate())
print(entry.has_ip)
print(entry.__repr__())

print("\n--------------------------------------------------\n")

journal = SSHLogJournal.SSHLogJournal()
journal.append("Dec 10 06:55:46 LabSZ sshd[24200]: reverse mapping checking getaddrinfo for ns.marryaldkfaczcz.com [173.234.31.186] failed - POSSIBLE BREAK-IN ATTEMPT!")
journal.append("Dec 10 09:11:22 LabSZ sshd[24439]: error: Received disconnect from 103.99.0.122: 14: No more user authentication methods available. [preauth]")
journal.append("Dec 10 11:04:43 LabSZ sshd[25544]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=183.62.140.253  user=root")

print(len(journal))
for entry in journal:
    print(entry)

print(journal[:1])

print(entry in journal)
print(journal["103.99.0.122"])

start_date = datetime.datetime(year=1900, month=12, day=10, hour=6, minute=55, second=43)
end_date = datetime.datetime(year=1900, month=12, day=10, hour=10, minute=4, second=43)
print(journal[(start_date, end_date)])
