import SSHLogEntry

entry = SSHLogEntry.classify_entry(
    "Dec 10 09:11:22 LabSZ sshd[24439]: error: Received disconnect from 103.99.0.122: 14: No more user authentication methods available. [preauth]")
print(entry)
print(entry.type)
print(entry.IPv4_address)
print(entry.validate())
