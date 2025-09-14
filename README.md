# IoC-Scanner

Outil **lecture seule** pour **détecter rapidement des IoC** (Indicators of Compromise) et des **points de persistance** courants sur Windows, macOS et Linux.  
Il peut aussi analyser des projets **npm** (packages installés et scripts d’installation).

📦 **Releases** : exécutables **GUI uniquement** pour Windows / Linux / macOS.  
La **CLI** reste disponible depuis les sources Python.

---

## ✨ Fonctionnalités

- Analyse **npm** : dépendances (node_modules) et scripts `install/postinstall…`
- Détection d’**IoC sysupdater** (par projet / globale)
- Signatures de **mineurs** (fichiers/processus connus)
- Inventaire de **persistance** par OS (Startup, services, LaunchAgents/Daemons, cron/systemd, etc.)
- Vérifications **réseau** (ports en écoute) et **système** (fichier `hosts`, profils shell…)
- Export **CSV** / **JSON**
- Interface **Graphique (Tkinter)** confortable ou **CLI** au choix

---

## 🔄 Mises à jour des signatures (IoC-Signatures)

Les listes/signatures utilisées par IoC-Scanner proviennent du dépôt **Emzime/IoC-Signatures** :  
➡️ https://github.com/Emzime/IoC-Signatures

### Option A — Mise à jour **automatique** (script recommandé)
Le dépôt *IoC-Signatures* fournit un script `update_defaults.py` qui met à jour directement les valeurs par défaut de **IoC-Scanner** (dans `scanner/refs/*.py`).  
Il réécrit les constantes `DEFAULT_*` (packages à risque, cibles supplémentaires, indices de mineurs, motifs suspects, etc.).

**Exécution :**
```bash
# À côté de ton dépôt IoC-Scanner
git clone https://github.com/Emzime/IoC-Signatures.git ioc-sigs
cd ioc-sigs

# Met à jour les DEFAULT_* dans le dossier IoC-Scanner ciblé
python update_defaults.py ../IoC-Scanner
# (Windows) si besoin : py -3 update_defaults.py ..\IoC-Scanner
```

### Option B — Mise à jour **manuelle**
Copie les JSON **depuis IoC-Signatures** vers `scanner/refs/` :
```bash
git clone https://github.com/Emzime/IoC-Signatures.git ioc-sigs
cp -v ioc-sigs/bad_packages.json         scanner/refs/
cp -v ioc-sigs/targets.json              scanner/refs/
cp -v ioc-sigs/miner_file_hints.json     scanner/refs/
cp -v ioc-sigs/miner_proc_hints.json     scanner/refs/
cp -v ioc-sigs/suspicious_patterns.json  scanner/refs/
```

### Option C — **Submodule git** (pour suivre facilement les mises à jour)
```bash
git submodule add https://github.com/Emzime/IoC-Signatures.git vendor/IoC-Signatures
git submodule update --init --recursive
# Quand tu veux mettre à jour :
git submodule update --remote --merge
# puis lance Option A (script) ou recopie manuellement vers scanner/refs/
```

ℹ️ Les **releases** embarquent un **instantané** des signatures au moment du build. Pour bénéficier des dernières signatures dans les binaires, récupère la **prochaine release** ou utilise l’outil **depuis les sources** en mettant à jour `scanner/refs/` comme ci-dessus.

---

## 📥 Installation & Lancement

### Option 1 — Utiliser le GUI fourni (recommandé)
1. Télécharge l’exécutable correspondant à ton OS depuis **Releases**.
2. Lance l’exécutable :
   - Windows : `IoC-Scanner_Windows_vX.Y.Z.exe`
   - Linux   : `IoC-Scanner_Linux_vX.Y.Z`
   - macOS   : `IoC-Scanner_macOS_vX.Y.Z`

ℹ️ **Icône de fenêtre** : par design, l’icône est chargée **à l’exécution** depuis des assets embarqués (pour réduire les faux positifs AV).  
Si l’OS affiche l’icône “générique” dans l’explorateur, c’est normal : la **barre de titre/Dock** affiche l’icône de l’app.

### Option 2 — Depuis les sources (CLI ou GUI)

**Prérequis**
- Python **3.9+** (recommandé : **3.11–3.13**)
- Linux : `python3-tk` (Tkinter) pour la GUI

```bash
# 1) Cloner
git clone <url-du-repo>
cd IoC-Scanner

# 2) (Optionnel) créer un venv
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

# 3) Installer les dépendances si requirements.txt est présent
pip install -r requirements.txt  # sinon, ignorer

# 4a) Lancer la GUI
python -m scanner.main --gui

# 4b) Utiliser la CLI (voir --help)
python -m scanner.main --help
```

---

## 🖥️ Interface Graphique (GUI)

- Choisis la **racine à scanner**, les **exclusions**, la **profondeur**, puis les **types de scan**.
- Suis la barre de progression et les **logs** en temps réel.
- Exporte les résultats **CSV** (ou **JSON**) si besoin.

ℹ️ L’icône de la fenêtre Tk est chargée au démarrage à partir d’assets embarqués (`assets/icon.ico` sur Windows, `assets/icon.png` ailleurs).

---

## 🧪 Interface en Ligne de Commande (CLI)

Aide intégrée :
```bash
python -m scanner.main --help
```

### Arguments principaux
```
-r, --root PATH            Racine à scanner (par défaut: auto selon OS)
-x, --exclude CSV          Dossiers à exclure (séparés par des virgules)

--no-npm                   Désactive l’analyse des packages npm
--only-risk                N’affiche que les paquets à risque
--no-scripts               N’analyse pas les scripts npm
--sysupdater-project       IoC .sysupdater.dat (par projet)
--sysupdater-global        IoC .sysupdater.dat (global, plus lent)
--miners                   Détection mineurs (fichiers/process)
--persistence              Persistance (mécanismes de démarrage)
--hosts                    Contrôle du fichier hosts
--net-listen               Ports en écoute (sockets ouverts)
--shell-profiles           Profils shell (~/.bashrc, ~/.zshrc…)

# Windows spécifiques
--startup                  Dossiers de démarrage
--services                 Services auto
--defender-exclusions      Exclusions Windows Defender
--proxy                    Paramètres proxy utilisateur
--wmi                      Abonnements WMI2

# macOS spécifiques
--launch-globals           LaunchDaemons/Agents globaux
--login-items              Éléments d’ouverture (login items)
--profiles                 Profils de configuration

# Linux spécifiques
--cron-system              Cron système (/etc/cron.*, /etc/cron.d, etc.)
--systemd-system           Unités systemd (niveau système)
--ld-preload               Fichier /etc/ld.so.preload
--suid                     Binaires SUID/SGID
--path-world-writable      Répertoires world-writable dans $PATH

# Sorties / général
--csv PATH                 Fichier CSV de sortie
--json PATH                Fichier JSON de sortie
--delimiter CHAR           Délimiteur CSV (par défaut culturel)
--max-depth INT            Profondeur max (défaut: 6)
--follow-links             Suivre les liens symboliques
--verbose                  Logs détaillés
--gui                      Lance l’interface graphique
--exec-timeout INT         Timeout (s) des commandes externes (défaut: 60)
```

**Exemples**
```bash
# Scan rapide d’un projet npm + persistance OS, export CSV
python -m scanner.main -r "C:\Projets\mon-app" --persistence --csv "rapport.csv"

# Recherche IoC sysupdater partout sous /home/user, uniquement risques, logs détaillés
python -m scanner.main -r "/home/user" --sysupdater-global --only-risk --verbose
```

**Astuce**
- `IOC_MAX_DISPLAY` (env) limite le nombre de lignes affichées en console (défaut : 300).

---

## 📄 Sorties

- **Console** : résumé et premières lignes (jusqu’à `IOC_MAX_DISPLAY`).
- **CSV** : délimiteur auto selon locale (ou `--delimiter`).
- **JSON** : enregistrement brut des résultats.

---

## 📄 Build local (PyInstaller)

> Les releases officielles sont générées via GitHub Actions.  

### Localement, tu peux produire un binaire portable.

```powershell
pyinstaller `
  --noconfirm --onefile --clean --noupx `
  --windowed `
  --name IoC-Scanner_Windows_Local `
  --add-data "scanner\assets\icon.ico;assets" `
  --add-data "scanner\assets\icon.png;assets" `
  entry_gui.py
```

### Alternative : `--onedir` (réduit les heuristiques AV).

```powershell
pyinstaller `
  --noconfirm --onedir --clean --noupx `
  --windowed `
  --name IoC-Scanner_Windows_Local `
  --add-data "scanner\assets\icon.ico;assets" `
  --add-data "scanner\assets\icon.png;assets" `
  entry_gui.py
```

### Linux
```bash
pyinstaller --noconfirm --onefile --clean --noupx \
  --windowed \
  --name IoC-Scanner_Linux_Local \
  --icon scanner/assets/icon.png \
  --add-data "scanner/assets/icon.png:assets" \
  entry_gui.py
```

### macOS
Génère l’icône `.icns` depuis le PNG (via `sips` + `iconutil`) **avant** le build, une fonction est déjà présente dans release.yml :
```bash
# génération icns (exemple)
mkdir -p scanner/assets/icon.iconset
for s in 16 32 64 128 256 512; do
  sips -z $s $s scanner/assets/icon.png --out scanner/assets/icon.iconset/icon_${s}x${s}.png >/dev/null
  s2=$((s*2))
  sips -z $s2 $s2 scanner/assets/icon.png --out scanner/assets/icon.iconset/icon_${s}x${s}@2x.png >/dev/null
done
iconutil -c icns scanner/assets/icon.iconset -o scanner/assets/icon.icns

# build
pyinstaller --noconfirm --onefile --clean --noupx \
  --windowed \
  --name IoC-Scanner_macOS_Local \
  --icon scanner/assets/icon.icns \
  --add-data "scanner/assets/icon.png:assets" \
  entry_gui.py
```

---

## 🔐 Sécurité & confidentialité

- **Lecture seule** : l’outil n’écrit pas dans tes projets/système (hors fichiers d’export, si demandés).
- Certaines vérifications utilisent des commandes système (ex. liste des sockets).  
- Les binaires **ne téléversent aucune donnée**.

---

## 📜 Licence

Ce projet est distribué sous la licence MIT.<br>
Vous êtes libre d’utiliser, copier, modifier, fusionner, publier, distribuer, sous-licencier et/ou vendre des copies du logiciel, sous réserve d’inclure le texte de la licence MIT dans toute copie ou partie substantielle du logiciel.<br>
Voir le fichier [LICENSE](./LICENSE) pour plus de détails.

---

## ❓FAQ rapide

**Q. L’icône n’apparaît pas dans l’explorateur Windows ?**  
R. C’est normal si on n’utilise pas `--icon` (pour éviter des heuristiques AV).  
La **fenêtre** affiche bien l’icône (chargée au runtime).  

**Q. Le binaire déclenche un antivirus ?**  
R. Les heuristiques varient. Les releases sont configurées pour minimiser les faux positifs (pas d’UPX, manifest propre, icône chargée au runtime).  
En cas de souci, préfère la version **onedir** ou exécute depuis les **sources**.
