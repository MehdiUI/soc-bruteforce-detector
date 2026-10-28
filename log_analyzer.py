import re
from collections import Counter

PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)
compteur = Counter()                                # ← LA LIGNE MANQUANTE

try:
    with open("auth.log", "r") as f:
        for line in f:
            match = PATTERN.search(line)
            if match:
                user = match.group(1)
                ip   = match.group(2)
                compteur[ip] += 1

    print(compteur)

except FileNotFoundError:
    print("Le fichier auth.log est introuvable.")