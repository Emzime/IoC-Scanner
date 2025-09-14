# IoC Scanner

Scanner multi-OS (Windows / macOS / Linux) pour détecter :
- paquets **npm** compromis (arbre `npm ls`, *lockfiles*),
- **IoC** courants (ex. `.sysupdater.dat`),
- **scripts suspects** (npm `postinstall`, `curl | bash`, etc.),
- **persistance** OS (Scheduled Tasks / LaunchAgents / crontab / systemd user),
- **mineurs** (fichiers & processus),
- anomalies **réseau** (ports en écoute),
- entrées **hosts**, **profils shell**…

Deux interfaces : **CLI** et **GUI** (Tkinter).

---
## Installation rapide
```bash
# Cloner (ou copier les fichiers) puis entrer dans le dossier
git clone https://github.com/Emzime/IoC-Scanner.git
cd IoC-Scanner

# Exécution directe
python -m scanner.cli --help

# Installation locale editable (recommandé pour dev)
pip install -e .
```

> Sous Windows, utilisez **PowerShell** et `py -m pip install -e .` si besoin.

---
## Prérequis
- **Python 3.9+** (testé 3.9–3.12)
- Tkinter (pour la GUI) — déjà présent sur Windows/macOS ; sur Linux :  
  `sudo apt install python3-tk`
- Accès aux utilitaires système :
  - Windows : `wmic`, `powershell`, `schtasks`, `netstat`, `tasklist`.
  - Linux : `ps`, `ss` ou `lsof`, `systemctl`, `crontab`, `find`.
  - macOS : `launchctl`, `osascript`, `profiles`.
---

## Utilisation

### CLI
```bash
python -m scanner.cli [options]
```

Options clés :
- `-r, --root PATH` : racine à scanner (`/` ou `C:\`).
- `-x, --exclude "dir1,dir2"` : dossiers à exclure.
- `--only-risk` : n’affiche que les paquets npm compromis.
- `--no-npm` : désactive l’analyse npm.
- `--no-scripts` : ignore l’inspection des scripts npm.
- `--miners` : signatures mineurs (fichiers + processus).
- `--persistence` : persistance OS.
- **Windows** : `--startup`, `--services`, `--defender-exclusions`, `--proxy`, `--wmi`.
- **macOS** : `--launch-globals`, `--login-items`, `--profiles`.
- **Linux** : `--cron-system`, `--systemd-system`, `--ld-preload`, `--suid`, `--path-world-writable`.
- `--csv PATH`, `--json PATH` : sorties.
- Divers : `--max-depth N`, `--follow-links`, `--verbose`, `--exec-timeout SECS`
- `--gui` : lance l’interface graphique.

### GUI
```bash
python -m scanner.cli --gui
# ou simplement sans argument (si un affichage est détecté)
python -m scanner.cli
```

---
## Exemples
```bash
# Scan npm minimal sur le projet courant
python -m scanner.cli -r . --only-risk

# IoC sysupdater + mineurs + persistance utilisateur
python -m scanner.cli -r / --sysupdater-project --miners --persistence --verbose

# Audit réseau et hosts, export CSV/JSON
python -m scanner.cli -r / --hosts --net-listen --csv ./rapport.csv --json ./rapport.json

# Windows : services auto + startup + exclusions Defender
python -m scanner.cli --services --startup --defender-exclusions

# Linux : cron système + systemd + LD_PRELOAD + PATH world-writable
python -m scanner.cli --cron-system --systemd-system --ld-preload --path-world-writable

# Utiliser un dépôt de signatures personnalisé (Linux/macOS bash/zsh)
export IOC_SIGNATURES_URL="https://raw.githubusercontent.com/MonOrga/MesSignatures/main"
python -m scanner.cli -r . --only-risk

# Utiliser un dépôt de signatures personnalisé (Windows PowerShell)
$env:IOC_SIGNATURES_URL="https://raw.githubusercontent.com/MonOrga/MesSignatures/main"
python -m scanner.cli -r . --only-risk
```

---
## Options CLI (exhaustives)
| Option | Description |
|--------|-------------|
| `-r, --root PATH` | Racine à scanner (défaut `/` ou `C:\`). |
| `-x, --exclude LISTE` | Dossiers à exclure (séparés par des virgules). |
| `--no-npm` | Désactive l’analyse des projets npm. |
| `--only-risk` | Affiche uniquement les paquets npm compromis. |
| `--no-scripts` | N’analyse pas les scripts npm (`install`, `postinstall`, etc.). |
| `--sysupdater-project` | Recherche `.sysupdater.dat` dans les projets npm. |
| `--sysupdater-global` | Recherche `.sysupdater.dat` globalement sous la racine (lent). |
| `--miners` | Détection de mineurs (fichiers + processus). |
| `--persistence` | Recherche de mécanismes de persistance OS (cron, tasks, launch agents…). |
| `--hosts` | Vérifie les entrées suspectes du fichier `hosts`. |
| `--net-listen` | Liste les ports en écoute et met en avant certains ports courants. |
| `--shell-profiles` | Analyse les profils shell (`.bashrc`, `.zshrc`, etc.). |
| `--startup` | Windows : vérifie les dossiers de démarrage. |
| `--services` | Windows : liste les services configurés en auto. |
| `--defender-exclusions` | Windows : liste les exclusions de Windows Defender. |
| `--proxy` | Windows : lit la config proxy dans le registre. |
| `--wmi` | Windows : recherche de persistance WMI. |
| `--launch-globals` | macOS : liste les LaunchDaemons/Agents globaux. |
| `--login-items` | macOS : liste les éléments ouverts automatiquement à la connexion. |
| `--profiles` | macOS : liste les profils de configuration installés. |
| `--cron-system` | Linux : analyse les tâches cron système. |
| `--systemd-system` | Linux : analyse les unités systemd système. |
| `--ld-preload` | Linux : vérifie `/etc/ld.so.preload`. |
| `--suid` | Linux : recherche des binaires SUID/SGID. |
| `--path-world-writable` | Linux : détecte les répertoires du PATH modifiables par tous. |
| `--csv FILE` | Écrit les résultats dans un fichier CSV. |
| `--json FILE` | Écrit les résultats dans un fichier JSON. |
| `--delimiter CHAR` | Délimiteur CSV (défaut auto selon locale). |
| `--max-depth N` | Profondeur max de parcours des dossiers (défaut : 6). |
| `--follow-links` | Suit les liens symboliques. |
| `--verbose` | Journal détaillé (affiche chaque répertoire analysé). |
| `--gui` | Lance l’interface graphique. |
| `--exec-timeout SECS` | Timeout global des commandes externes (défaut : 60s). |
| `--update-signatures` | Met à jour les signatures IoC depuis le dépôt en ligne. |

## Sorties (CSV / JSON)
- **CSV** : UTF-8-BOM, délimiteur auto (`,` ou `;` selon locale).  
- **JSON** : liste d’objets.

---
## Architecture
```
IoC-Scanner
├─ main.py
└─ scanner/
   ├─ cli.py
   ├─ gui.py
   ├─ utils.py
   ├─ core/
   │  ├─ common.py
   │  ├─ linux.py
   │  ├─ mac.py
   │  └─ win.py
   └─ refs/
      ├─ labels.py
      ├─ miners.py
      ├─ packages.py
      └─ publishers.py
```

---
## Variables d’environnement utiles
| Variable | Rôle |
|----------|------|
| `IOC_APP_NAME` | Change le nom de l’application (impacte le dossier `Documents/<AppName>` et la GUI). |
| `IOC_MAX_DISPLAY` | Nombre max. de lignes affichées en console (défaut 300). |
| `PYTHONIOENCODING` | Forcer l’encodage de sortie. |
| `IOC_SIGNATURES_URL` | **URL du dépôt de signatures IoC**. Par défaut : `https://raw.githubusercontent.com/Emzime/IoC-Signatures/main`. Permet de pointer vers un autre dépôt (public, privé, enterprise, interne). |

---
## Usage avec un dépôt de signatures personnalisé
Par défaut, le scanner utilise :  
`https://raw.githubusercontent.com/Emzime/IoC-Signatures/main`

Grâce à `IOC_SIGNATURES_URL`, vous pouvez utiliser un autre dépôt.

### Cas 1 : Repo public GitHub
```bash
export IOC_SIGNATURES_URL="https://raw.githubusercontent.com/MonOrga/MesSignatures/main"
python -m scanner.cli --only-risk
```

```powershell
$env:IOC_SIGNATURES_URL="https://raw.githubusercontent.com/MonOrga/MesSignatures/main"
python -m scanner.cli --only-risk
```

### Cas 2 : Repo privé GitHub
1. Créez un **token** (PAT) avec droits `Contents: Read`.  
2. Construisez l’URL ainsi :  
   ```
   https://<TOKEN>@raw.githubusercontent.com/<OWNER>/<REPO>/main
   ```

Exemple Linux/macOS :
```bash
export IOC_SIGNATURES_URL="https://ghp_xxxTOKENxxx@raw.githubusercontent.com/MonOrga/MesSignatures/main"
python -m scanner.cli -r / --miners
```

Exemple PowerShell :
```powershell
$env:IOC_SIGNATURES_URL="https://ghp_xxxTOKENxxx@raw.githubusercontent.com/MonOrga/MesSignatures/main"
python -m scanner.cli -r C:\ --miners
```

⚠️ Le token est visible → préférez un `.env` ou un secret CI/CD.

### Cas 3 : GitHub Enterprise
```bash
export IOC_SIGNATURES_URL="https://raw.githubusercontent.com/ton-instance/MonOrga/MesSignatures/main"
```

### Cas 4 : Serveur interne HTTP/HTTPS
```bash
export IOC_SIGNATURES_URL="https://intranet.example.com/ioc-rules"
```

Le scanner téléchargera :
- `${IOC_SIGNATURES_URL}/bad_packages.json`
- `${IOC_SIGNATURES_URL}/targets.json`
- `${IOC_SIGNATURES_URL}/miner_file_hints.json`
- `${IOC_SIGNATURES_URL}/miner_proc_hints.json`
- `${IOC_SIGNATURES_URL}/suspicious_patterns.json`

---
## Tests
```bash
pytest -q
```

Idées de tests :
- Simuler un `package.json` compromis.  
- Vérifier l’exclusion `.vscode/extensions`.  
- Forcer `IOC_SIGNATURES_URL` sur un repo de test.

---
## Licence
Ce projet est distribué sous la licence **MIT**.
<br>
Vous êtes libre d’utiliser, copier, modifier, fusionner, publier, distribuer, sous-licencier et/ou vendre des copies du logiciel, sous réserve d’inclure le texte de la licence MIT dans toute copie ou partie substantielle du logiciel.
<br>
Voir le fichier [LICENSE](LICENSE) pour plus de détails.
<br>
<br>
<br>
<br>