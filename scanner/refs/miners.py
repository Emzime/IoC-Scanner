# scanner/refs/miners.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import re
from typing import List

from scanner.utils import fetch_json, SIGNATURE_BASE_URL, CACHE_DIR


# ---------------------------------------------------------------------------
# Valeurs de secours (utilisées si le dépôt de signatures est indisponible)
# ---------------------------------------------------------------------------

# BEGIN DEFAULT_MINER_FILE_HINTS (AUTO)
DEFAULT_MINER_FILE_HINTS: List[str] = [
    "xmrig(\.exe)?$",
    "lolminer(\.exe)?$",
    "nbminer(\.exe)?$",
    "ethminer(\.exe)?$",
    "teamredminer(\.exe)?$",
    "t-rex(\.exe)?$",
    "gminer(\.exe)?$",
    "phoenixminer(\.exe)?$",
    "astrominer(\.exe)?$",
    "cpuminer(\.exe)?$",
    "minerd(\.exe)?$",
    "__test__fake_miner(\.exe)?$"
]
# END DEFAULT_MINER_FILE_HINTS (AUTO)

# BEGIN DEFAULT_MINER_PROC_HINTS (AUTO)
DEFAULT_MINER_PROC_HINTS: List[str] = [
    "\bxmrig\b",
    "\blolminer\b",
    "\bnbminer\b",
    "\bethminer\b",
    "\bteamredminer\b",
    "\bt-rex\b",
    "\bgminer\b",
    "\bphoenixminer\b",
    "\bastrominer\b",
    "\bcpuminer\b",
    "\bminerd\b"
]
# END DEFAULT_MINER_PROC_HINTS (AUTO)

# BEGIN DEFAULT_SUSPICIOUS_SCRIPT_PATTERNS (AUTO)
DEFAULT_SUSPICIOUS_SCRIPT_PATTERNS: List[str] = [
    "curl\s+[^|]+?\|\s*(bash|sh|zsh|python|python3)",
    "wget\s+[^|]+?\|\s*(bash|sh|zsh|python|python3)",
    "Invoke-WebRequest.+\|\s*iex",
    "bitsadmin\s+/transfer",
    "powershell\.exe\s+-enc\s+[A-Za-z0-9+/=]+",
    "Add-MpPreference\s+-Exclusion(Path|Process|Extension)",
    "reg(?:\.exe)?\s+add\s+HK(?:CU|LM)\\",
    "(?:schtasks|at)\s+/create",
    "(?:crontab|systemctl)\s+(?:-|\w+)",
    "chmod\s+\+x\s+/tmp/.*",
    "base64\s+-d\s+.+\|\s*(bash|sh|zsh|python|python3)"
]
# END DEFAULT_SUSPICIOUS_SCRIPT_PATTERNS (AUTO)


# ---------------------------------------------------------------------------
# Helpers internes
# ---------------------------------------------------------------------------

def _ensure_str_list(value) -> List[str]:
    """Transforme une valeur JSON en liste de chaînes non vides (sinon [])."""
    if not isinstance(value, list):
        return []
    out: List[str] = []
    for v in value:
        if isinstance(v, str):
            v2 = v.strip()
            if v2:
                out.append(v2)
    return out


def _merge_unique(*seqs: List[str]) -> List[str]:
    """Fusionne plusieurs listes en dédupliquant, tout en conservant l'ordre."""
    seen = {}
    out: List[str] = []
    for seq in seqs:
        for s in seq:
            if s not in seen:
                seen[s] = True
                out.append(s)
    return out


# ---------------------------------------------------------------------------
# Chargement dynamique depuis le dépôt 'ioc-signatures'
# ---------------------------------------------------------------------------

_file_hints = _ensure_str_list(
    fetch_json(
        f"{SIGNATURE_BASE_URL}/miner_file_hints.json",
        CACHE_DIR / "miner_file_hints.json"
    ).get("patterns", [])
)

_proc_hints = _ensure_str_list(
    fetch_json(
        f"{SIGNATURE_BASE_URL}/miner_proc_hints.json",
        CACHE_DIR / "miner_proc_hints.json"
    ).get("patterns", [])
)

_script_patterns = _ensure_str_list(
    fetch_json(
        f"{SIGNATURE_BASE_URL}/suspicious_patterns.json",
        CACHE_DIR / "suspicious_patterns.json"
    ).get("patterns", [])
)

# Fusion avec les valeurs par défaut (permet de fonctionner hors-ligne)
MINER_FILE_HINTS: List[str] = _merge_unique(DEFAULT_MINER_FILE_HINTS, _file_hints)
MINER_PROC_HINTS: List[str] = _merge_unique(DEFAULT_MINER_PROC_HINTS, _proc_hints)
SUSPICIOUS_SCRIPT_PATTERNS: List[str] = _merge_unique(DEFAULT_SUSPICIOUS_SCRIPT_PATTERNS, _script_patterns)

# Heuristique CLI des mineurs (locale)
SUSPICIOUS_CLI_REGEX = re.compile(
    r"(?:^|\s)(?:--donate-level|--algo|--coin|--rig-id|--user|--pass|"
    r"--url\s+\w+://|stratum\+\w*://|pool\.)",
    re.IGNORECASE,
)

__all__ = [
    "MINER_FILE_HINTS",
    "MINER_PROC_HINTS",
    "SUSPICIOUS_CLI_REGEX",
    "SUSPICIOUS_SCRIPT_PATTERNS",
]
