# 🔐 SOC Brute-Force Detector


Script Python léger pour analyser les fichiers `auth.log` (Debian/Ubuntu) et détecter les tentatives de brute force SSH, en signalant les adresses IP suspectes qui dépassent un seuil configurable.

## 🎯 Objectif

Automatiser le triage de journaux d'authentification — une tâche répétitive mais critique en SOC. Ce script transforme un fichier de logs brut en rapport d'alerte lisible, en détectant les IP qui génèrent un nombre anormal d'échecs de connexion SSH.

## 🎓 Compétences démontrées

- **Python** : parsing de fichiers, expressions régulières, `collections.Counter`, refactor en fonctions, gestion d'erreurs (`try/except`), docstrings
- **Analyse de logs** : format `auth.log`, extraction user/IP, distinction échec/succès, gestion des formats `invalid user`
- **Détection SOC** : logique de seuil, triage par sévérité, ground truth de test, documentation des limitations
- **Git** : commits atomiques, `.gitignore`, README structuré

## 🧠 Logique de détection

Le script se base sur le format standard des échecs SSH dans `auth.log` :

```
Failed password for <user> from <ip> port <port> ssh2
Failed password for invalid user <user> from <ip> port <port> ssh2
```

**Pipeline** :

1. **Parsing** — Une regex extrait le nom d'utilisateur et l'IP source, avec gestion des cas `invalid user`.
2. **Agrégation** — Un `Counter` Python compte les échecs par IP source.
3. **Triage** — Les IP dépassant un seuil (par défaut : 5 échecs) sont affichées, **triées par gravité décroissante**.

## 🧩 Choix techniques

- **Regex ancrée** sur `Failed password` (et non un simple `for X from IP`) — évite de compter les connexions réussies comme des échecs.
- **Groupe non-capturant `(?:invalid user )?`** — couvre les deux formats OpenSSH (`for root from` et `for invalid user test from`) sans dupliquer la logique.
- **`collections.Counter`** plutôt qu'un dictionnaire manuel — agrégation idiomatique, tri par gravité gratuit via `.most_common()`.
- **Ground truth de test** — `generate_logs.py` génère 7 scénarios contrôlés, ce qui permet de valider la détection sans dépendre de vrais logs.
- **Point d'entrée explicite** (`if __name__ == "__main__"`) — le module peut être importé sans déclencher l'analyse.

## 🛠️ Utilisation

```bash
# 1. Générer un fichier auth.log synthétique (avec scénarios de test)
python generate_logs.py

# 2. Lancer l'analyse
python log_analyzer.py
```

## 📊 Exemple de sortie

```
=== IP suspectes (>= 5 échecs) ===
    8 échecs depuis 192.168.1.50
    6 échecs depuis 185.220.101.4
    5 échecs depuis 203.0.113.7
```

## 🎯 Scénarios détectés (ground truth)

Le fichier `auth.log` généré par `generate_logs.py` contient 7 scénarios contrôlés :

| Scénario | Échecs | Alerte attendue |
|---|---|---|
| Brute force sur `root` depuis `192.168.1.50` | 8 | ✅ OUI |
| Brute force sur `admin` depuis `185.220.101.4` | 6 | ✅ OUI |
| Scan d'utilisateurs inexistants depuis `203.0.113.7` | 5 | ✅ OUI (seuil=5) |
| Erreurs `alice` depuis `10.0.0.12` | 4 | ❌ non (faux positif évité) |
| Erreurs isolées `devops` (5 IPs distinctes) | 1 chacune | ❌ non |
| Connexions légitimes (bruit de fond) | 15 `Accepted` | ❌ non |
| 3 échecs + 1 succès `deploy` | 3 | ❌ non (bonus v2) |

## ⚙️ Configuration

Le seuil d'alerte est défini en tête de `log_analyzer.py` :

```python
SEUIL = 5  # nombre minimum d'échecs pour déclencher une alerte
```

## 🚧 Limitations connues

- Ne détecte que les échecs par **password** (pas `publickey`).
- Pas de fenêtre temporelle (une IP lente mais persistante pourrait passer sous le seuil).
- Pas de corrélation échecs → succès (indicateur de compromission).
- Formats OpenSSH récents (`Connection closed by authenticating user`) non couverts.

Ces limitations sont documentées pour une v2 (voir section Roadmap).

