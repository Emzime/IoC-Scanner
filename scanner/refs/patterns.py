# scanner/refs/patterns.py
# -*- coding: utf-8 -*-
SUSPICIOUS_SCRIPT_PATTERNS = [
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
