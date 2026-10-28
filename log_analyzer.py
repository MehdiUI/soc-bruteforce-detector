"""
Analyseur de logs d'authentification SSH pour détecter les tentatives de brute force.

Lit un fichier auth.log (Debian/Ubuntu), extrait les échecs de connexion SSH,
compte les occurrences par adresse IP source et affiche les IP qui dépassent
un seuil configurable.

Usage :
    python log_analyzer.py
"""


import re
from collections import Counter

PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)
SEUIL = 5


def analyser_log(chemin):
    """Lit un fichier auth.log et renvoie un Counter des échecs par IP."""
    compteur = Counter()
    with open(chemin, "r", errors="ignore") as f:
        for line in f:
            match = PATTERN.search(line)
            if match:
                ip = match.group(2)
                compteur[ip] += 1
    return compteur


def afficher_alertes(compteur):
    """Affiche les IP qui dépassent le seuil, triées par gravité."""
    print(f"=== IP suspectes (>= {SEUIL} échecs) ===")
    for ip, count in compteur.most_common():
        if count < SEUIL:
            break
        print(f"  {count:>3} échecs depuis {ip}")


if __name__ == "__main__":
    try:
        compteur = analyser_log("auth.log")
        afficher_alertes(compteur)
    except FileNotFoundError:
        print("Le fichier auth.log est introuvable.")