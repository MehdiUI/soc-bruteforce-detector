import re

line = "Jan 15 10:00:12 server sshd[4521]: Failed password for root from 192.168.1.50 port 33110 ssh2"

pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"   # ← À TOI DE REMPLIR

match = re.search(pattern, line)
if match:
    print("IP trouvée :", match.group())
else:
    print("Pas de match")

