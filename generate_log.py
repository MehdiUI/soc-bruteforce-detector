"""
Génère un fichier auth.log synthétique avec des scénarios contrôlés.
Chaque scénario est documenté pour servir de "ground truth" aux tests.
"""

import random
from datetime import datetime, timedelta

random.seed(42)  # reproductibilité : même fichier à chaque exécution
events = []
start = datetime(2024, 1, 15, 10, 0, 0)


def add(offset_sec, msg):
    """Ajoute un événement avec un timestamp = start + offset."""
    dt = start + timedelta(seconds=offset_sec)
    pid = random.randint(1000, 9999)
    port = random.randint(30000, 65000)
    events.append(
        f"{dt.strftime('%b %d %H:%M:%S')} server sshd[{pid}]: {msg} port {port} ssh2"
    )


# ===== SCÉNARIO 1 : Brute force SSH sur 'root' depuis 192.168.1.50 =====
# 8 échecs en ~1min30 → DOIT déclencher une alerte
for i in range(8):
    add(i * 12, "Failed password for root from 192.168.1.50")

# ===== SCÉNARIO 2 : Brute force SSH sur 'admin' depuis 185.220.101.4 =====
# 6 échecs répartis sur ~2 min → DOIT déclencher une alerte
for i in range(6):
    add(300 + i * 20, "Failed password for admin from 185.220.101.4")

# ===== SCÉNARIO 3 : Scan d'utilisateurs inexistants depuis 203.0.113.7 =====
# 5 échecs sur 'invalid user' → détecte un scan de comptes
# DOIT déclencher une alerte si seuil=5
users_test = ["test", "oracle", "postgres", "ubnt", "pi"]
for i, u in enumerate(users_test):
    add(600 + i * 15, f"Failed password for invalid user {u} from 203.0.113.7")

# ===== SCÉNARIO 4 : Utilisateurs légitimes qui se trompent (bruit) =====
# 4 échecs sur 'alice' depuis 10.0.0.12, répartis sur 2h → NE DOIT PAS alerter
for i in range(4):
    add(900 + i * 1800, "Failed password for alice from 10.0.0.12")

# ===== SCÉNARIO 5 : Échecs isolés depuis IPs variées (bruit) =====
# 5 échecs, 5 IPs différentes, 1 chacun → NE DOIT PAS alerter
for i in range(5):
    add(1200 + i * 600, f"Failed password for devops from 10.0.0.{100+i}")

# ===== SCÉNARIO 6 : Connexions légitimes réussies (bruit de fond) =====
for i in range(15):
    add(random.randint(0, 7200),
        f"Accepted password for ubuntu from 10.0.0.{random.randint(1, 50)}")

# ===== SCÉNARIO 7 : Échecs PUIS succès (indicateur de compromission) =====
# 3 échecs puis 1 succès pour 'deploy' depuis 198.51.100.22
# Bonus : un vrai SIEM alerterait ici même si le seuil n'est pas atteint
for i in range(3):
    add(3000 + i * 10, "Failed password for deploy from 198.51.100.22")
add(3100, "Accepted password for deploy from 198.51.100.22")


# ===== Écriture du fichier (trié par timestamp) =====
events.sort(key=lambda line: line[:15])  # tri lexicographique = tri chronologique ici

with open("auth.log", "w") as f:
    for line in events:
        f.write(line + "\n")

print(f"✅ auth.log généré : {len(events)} lignes")