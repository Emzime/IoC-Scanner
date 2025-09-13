# scanner/refs/miners.py
# -*- coding: utf-8 -*-
from __future__ import annotations
import re
from typing import List, Pattern

MINER_FILE_HINTS: List[str] = [
    r"xmrig(\.exe)?$",
    r"phoenixminer(\.exe)?$",
    r"nanominer(\.exe)?$",
    r"nbminer(\.exe)?$",
    r"t-rex(\.exe)?$",
    r"lolminer(\.exe)?$",
]

MINER_PROC_HINTS: List[str] = [
    r"xmrig",
    r"phoenixminer",
    r"nanominer",
    r"nbminer",
    r"t-rex",
    r"lolminer",
]

SUSPICIOUS_CLI_REGEX: Pattern[str] = re.compile(
    r"(--donate-level|--algo|--coin|--url\s+\w+://|--rig-id|stratum\+\w*://|pool\.)",
    re.IGNORECASE,
)

SUSPICIOUS_SCRIPT_PATTERNS: List[str] = [
    r"curl\s+.+\|\s*(sh|bash|powershell|pwsh)",
    r"Invoke-WebRequest",
    r"\biwr\b",
    r"Start-Process\s+.+\.exe",
    r"powershell\s+-(?:EncodedCommand|enc|e)\b",
    r"cmd\s*/c\s+bitsadmin",
    r"bitsadmin\s+/(?:transfer|addfile)\b",
    r"mshta\s+",
    r"wscript\.shell",
    r"reg\s+add\s+HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    r"base64\s",
]
