# scanner/utils.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import csv, json, hashlib, locale, os, re, shutil, stat, subprocess, sys, requests, time

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# --- Détection d'OS ---
IS_WIN = os.name == "nt"
IS_MAC = sys.platform == "darwin"
IS_LIN = sys.platform.startswith("linux")

# --- Timeout global pour les commandes externes (surchargé par options.exec_timeout) ---
EXEC_TIMEOUT: int = 60

# URL du dépôt
SIGNATURE_BASE_URL = os.environ.get(
    "IOC_SIGNATURES_URL",
    "https://raw.githubusercontent.com/Emzime/IoC-Signatures/main"
)

CACHE_DIR = Path.home() / ".ioc_scanner"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

def fetch_json(url: str, cache_file: Path, max_age: int = 86400) -> dict:
    """
    Télécharge un JSON distant avec fallback sur un cache local.
    Max_age : durée max du cache (secondes)
    """
    now = time.time()
    try:
        # utiliser le cache si pas trop vieux
        if cache_file.exists() and (now - cache_file.stat().st_mtime < max_age):
            return json.loads(cache_file.read_text(encoding="utf-8"))

        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        # mettre à jour le cache
        cache_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return data

    except (requests.RequestException, json.JSONDecodeError) as e:
        print(f"[!] Erreur réseau/JSON pour {url}: {e}")

    except (OSError, IOError) as e:
        print(f"[!] Erreur fichier cache {cache_file}: {e}")

    # fallback si tout échoue
    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print(f"[!] Cache corrompu: {cache_file}")

    return {}

# ---------------------------------------------------------------------------
# Utilitaires système / fichiers
# ---------------------------------------------------------------------------

def get_default_root() -> str:
    """Racine par défaut (C :\\ sous Windows, / ailleurs)."""
    return "C:\\" if IS_WIN else "/"

def _sanitize_fs_name(name: str, fallback: str = "Rapports") -> str:
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', " ", name).strip()
    name = re.sub(r"\s+", " ", name)
    return name or fallback

def get_documents_dir() -> Path:
    """Répertoire Documents de l’utilisateur (fallback : $HOME)."""
    home = Path.home()
    doc = home / "Documents"
    return doc if doc.exists() else home

def get_app_name(default: str = "IoC-Scanner") -> str:
    """Nom humain de l’app (env IOC_APP_NAME > nom du script)."""
    env = os.environ.get("IOC_APP_NAME")
    if env:
        return _sanitize_fs_name(env)
    stem = Path(sys.argv[0] or __file__).stem
    if stem.lower() in {"main", "app", "run", "cli"}:
        return _sanitize_fs_name(default)
    human = re.sub(r"[-_]+", " ", stem).strip().title()
    return _sanitize_fs_name(human or default)

def get_reports_dir() -> Path:
    """Dossier ‘Documents/<AppName>’ (créé si absent)."""
    base = get_documents_dir() / get_app_name()
    base.mkdir(parents=True, exist_ok=True)
    return base

def default_output_path(ext: str) -> str:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return str(get_reports_dir() / f"rapport-{ts}.{ext}")

def default_exclude_names() -> List[str]:
    """Valeurs par défaut d’exclusions selon l’OS."""
    if IS_WIN:
        return [
            "Windows", "Program Files", "Program Files (x86)", "ProgramData",
            "AppData", "PerfLogs", "$Recycle.Bin", "System Volume Information",
            "Recovery", "Windows.old", "extensions",
        ]
    elif IS_MAC:
        return [
            "System", "Library", "Applications", "Volumes", "private",
            "usr", "bin", "sbin", "opt", "var", "dev", "cores", "Network",
        ]
    else:
        return [
            "proc", "sys", "dev", "run", "var", "tmp", "boot",
            "lib", "lib64", "usr", "bin", "sbin", "opt", "snap",
            "mnt", "media", "root",
        ]

def default_exclude_csv() -> str:
    return ",".join(default_exclude_names())

def default_csv_delimiter() -> str:
    """
    Choisit ',' ou ';' selon le séparateur décimal local.
    (Si décimal = ',', alors délimiteur CSV = ';')
    """
    dec = "."
    try:
        dp = locale.localeconv().get("decimal_point")
        if isinstance(dp, str) and dp:
            dec = dp
    except locale.Error:
        pass

    if dec == ".":
        # Tentative de lecture locale "par défaut" pour environnements non initialisés
        try:
            current = locale.setlocale(locale.LC_NUMERIC)
            try:
                locale.setlocale(locale.LC_NUMERIC, "")
                dp = locale.localeconv().get("decimal_point")
                if isinstance(dp, str) and dp:
                    dec = dp
            finally:
                if current:
                    try:
                        locale.setlocale(locale.LC_NUMERIC, current)
                    except locale.Error:
                        pass
        except locale.Error:
            pass

    return ";" if dec == "," else ","

# ---------------------------------------------------------------------------
# E/S JSON & CSV
# ---------------------------------------------------------------------------

def read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return None

def write_json(rows: List[Dict[str, str]], path: str) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(rows, fh, ensure_ascii=False, indent=2)

def write_csv(rows: List[Dict[str, str]], path: str, delimiter: str | None = None) -> None:
    """
    Écrit un CSV avec BOM UTF-8 pour Excel.
    Attend chaque ligne sous forme:
      {Category, Project, Item, Detail, Severity, (optionnel) SeverityText}
    """
    # import local pour éviter les cycles d'import
    from scanner.refs.labels import SEVERITY_LABEL

    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    effective_deli = (delimiter if delimiter and len(delimiter) == 1 else default_csv_delimiter())
    with out_path.open("w", encoding="utf-8-sig", newline="") as fh:
        fieldnames = ["Category", "Project", "Item", "Detail", "Severity", "SeverityText", "DescriptorPath"]
        writer = csv.DictWriter(fh, fieldnames=fieldnames, delimiter=effective_deli)
        writer.writeheader()
        for row_rec in rows:
            rec = dict(row_rec)
            rec["SeverityText"] = SEVERITY_LABEL.get(row_rec.get("Severity", ""), row_rec.get("Severity", ""))
            # si pas fourni par la ligne, laisser vide
            rec.setdefault("DescriptorPath", "")
            writer.writerow(rec)


# ---------------------------------------------------------------------------
# Exécution de commandes externes
# ---------------------------------------------------------------------------

def run_capture_ext(
    cmd: Sequence[str] | str,
    *,
    shell: bool = False,
    cwd: Optional[Path] = None,
    timeout: Optional[int] = None,
) -> Tuple[int, str, str]:
    """Exécute une commande et retourne (code, stdout, stderr)."""
    if timeout is None:
        timeout = EXEC_TIMEOUT
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except (subprocess.SubprocessError, OSError) as exc:
        return 1, "", str(exc)

def which(cmd: str) -> bool:
    """Retourne True si 'cmd' est résoluble dans le PATH."""
    return shutil.which(cmd) is not None

# ---------------------------------------------------------------------------
# Hash & heuristiques
# ---------------------------------------------------------------------------

def sha256_of(path: Path) -> str:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(8192), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return ""

def looks_user_or_temp(path: os.PathLike[str] | str) -> bool:
    """
    True si le chemin ressemble à un dossier utilisateur/temporaires
    (Windows/macOS/Linux). Sert à majorer la sévérité.
    """
    s = str(path).lower().replace("\\", "/")
    needles = (
        # Windows
        "/users/", "/appdata/", "/programdata/", "/temp/", "/windows/temp/",
        # Linux
        "/home/", "/tmp/", "/var/tmp/", "/var/run/", "/var/log/",
        # macOS
        "/users/", "/private/var/tmp/", "/private/var/folders/", "/var/folders/",
        "/library/caches/", "/library/launchagents/", "/library/launchdaemons/",
    )
    return any(n in s for n in needles)

# ---------------------------------------------------------------------------
# Process listing (multi-OS)
# ---------------------------------------------------------------------------

def list_processes() -> Iterable[tuple[str, int, str, Optional[str]]]:
    """
    Itère (name, pid, cmdline, user?) sur les processus.
    - Windows: wmic / tasklist (fallback)
    - Linux/mac: ps -e -o ...
    """
    if IS_WIN:
        code, out, _ = run_capture_ext(["wmic", "process", "get", "Name,ProcessId,CommandLine", "/FORMAT:CSV"])
        if code == 0 and out:
            rdr = csv.DictReader(out.splitlines())
            for rec in rdr:
                try:
                    name = (rec.get("Name") or "").strip()
                    pid = int((rec.get("ProcessId") or "0").strip() or "0")
                    cmd = (rec.get("CommandLine") or "").strip()
                    if name and pid:
                        yield name, pid, cmd, None
                except (ValueError, TypeError):
                    continue
        else:
            # Fallback: tasklist /V /FO CSV (cmdline indisponible)
            code2, out2, _ = run_capture_ext(["tasklist", "/V", "/FO", "CSV"])
            if code2 == 0 and out2:
                rdr = csv.DictReader(out2.splitlines())
                for rec in rdr:
                    name = (rec.get("Image Name") or rec.get("Nom de l'image") or "").strip()
                    pid_s = (rec.get("PID") or rec.get("Identificateur de processus") or "").strip()
                    try:
                        pid = int(pid_s)
                    except ValueError:
                        continue
                    yield name, pid, "", None
        return

    # Linux / macOS
    code, out, _ = run_capture_ext(["ps", "-e", "-o", "pid=,comm=,args=,user="])
    if code == 0 and out:
        pat = re.compile(r"^\s*(\d+)\s+(\S+)\s+(.*\S)?\s+(\S+)\s*$")
        for line in out.splitlines():
            m = pat.match(line)
            if not m:
                continue
            pid = int(m.group(1))
            comm = m.group(2) or ""
            args_part = (m.group(3) or "").strip()
            user = m.group(4) or None
            name = (args_part.split()[0] if args_part else comm)
            yield name, pid, args_part, user

# ---------------------------------------------------------------------------
# Divers Linux utiles (facultatif, mais pratique à centraliser)
# ---------------------------------------------------------------------------

def path_is_world_writable(p: Path) -> bool:
    """True si le répertoire est world-writable (bit 'others write')."""
    try:
        st = p.stat()
        return bool(stat.S_IWOTH & st.st_mode)
    except (OSError, PermissionError):
        return False

__all__ = [
    # OS flags / timeout
    "IS_WIN", "IS_MAC", "IS_LIN", "EXEC_TIMEOUT",
    # signatures auto-update
    "SIGNATURE_BASE_URL", "CACHE_DIR", "fetch_json",
    # chemins et noms
    "get_default_root", "get_documents_dir", "get_app_name", "get_reports_dir",
    "default_output_path", "default_exclude_names", "default_exclude_csv", "default_csv_delimiter",
    # E/S
    "read_json", "write_json", "write_csv",
    # exécution
    "run_capture_ext", "which",
    # hash & heuristiques
    "sha256_of", "looks_user_or_temp",
    # process
    "list_processes",
    # linux-tuning
    "path_is_world_writable",
]

