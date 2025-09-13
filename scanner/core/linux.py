# scanner/core/linux.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Iterable, List

from scanner.utils import IS_LIN, run_capture_ext, which, path_is_world_writable
from scanner.core.common import add_row
from scanner.refs.miners import SUSPICIOUS_CLI_REGEX

def scan_linux_cron_system(rows: List[Dict[str, str]], *, log=None) -> None:
    if not IS_LIN:
        return
    paths: Iterable[Path] = [Path("/etc/crontab"), *Path("/etc").glob("cron.*/*"), *Path("/etc/cron.d").glob("*")]
    for p in paths:
        try:
            if p.exists() and p.is_file():
                if log:
                    log(f"[v] Analyse cron système: {p}")
                for i, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    sev = "MEDIUM" if SUSPICIOUS_CLI_REGEX.search(s) else "INFO"
                    add_row(rows, "linux:cron", str(p), f"ligne {i}", s, sev)
        except (OSError, UnicodeError):
            if log:
                log(f"[!] Lecture impossible: {p}")

def scan_systemd_system(rows: List[Dict[str, str]], *, log=None) -> None:
    if not IS_LIN:
        return
    code, out, _ = run_capture_ext(["systemctl", "list-unit-files", "--type=service"])
    if code == 0 and out:
        if log:
            log("[v] systemd (système) listé")
        for line in out.splitlines():
            s = line.strip()
            if ".service" in s:
                add_row(rows, "linux:systemd", "system", "", s, "INFO")

def scan_ld_preload(rows: List[Dict[str, str]], *, log=None) -> None:
    if not IS_LIN:
        return
    p = Path("/etc/ld.so.preload")
    try:
        if p.exists():
            if log:
                log(f"[v] Lecture {p}")
            for i, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
                s = line.strip()
                if s:
                    add_row(rows, "linux:ld.so.preload", str(p), f"ligne {i}", s, "HIGH")
    except (OSError, UnicodeError):
        if log:
            log(f"[!] Lecture impossible: {p}")

def scan_suid_sgid(rows: List[Dict[str, str]], *, log=None) -> None:
    if not IS_LIN or not which("find"):
        return
    cmd = r'find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | head -n 1000'
    code, out, _ = run_capture_ext(cmd, shell=True)
    if code == 0 and out:
        if log:
            log("[v] Scan SUID/SGID")
        for line in out.splitlines():
            path = line.strip()
            if path:
                add_row(rows, "linux:suid_sgid", "", Path(path).name, path, "MEDIUM")

def scan_path_world_writable(rows: List[Dict[str, str]], *, log=None) -> None:
    if not IS_LIN:
        return
    seen = set()
    for d in (os.environ.get("PATH", "")).split(":"):
        if not d or d in seen:
            continue
        seen.add(d)
        p = Path(d)
        try:
            if path_is_world_writable(p):
                if log:
                    log(f"[v] PATH world-writable: {p}")
                add_row(rows, "linux:path", "", "world-writable", str(p), "HIGH")
        except OSError:
            if log:
                log(f"[!] Stat impossible: {p}")

def scan_persistence(rows: List[Dict[str, str]], *, log=None, verbose: bool=False) -> None:
    """Persistance utilisateur Linux: crontab + systemd --user."""
    if not IS_LIN:
        return
    code, out, _ = run_capture_ext(["crontab", "-l"])
    if code == 0 and out:
        if log and verbose:
            log("[v] crontab -l")
        for line in out.splitlines():
            entry_line = line.strip()
            if entry_line and not entry_line.startswith("#"):
                severity = "MEDIUM" if SUSPICIOUS_CLI_REGEX.search(entry_line) else "INFO"
                add_row(rows, "persist:crontab", "", "", entry_line, severity)

    if which("systemctl"):
        code, out, _ = run_capture_ext(["systemctl", "--user", "list-unit-files"])
        if code == 0 and out:
            if log and verbose:
                log("[v] systemctl --user list-unit-files")
            for line in out.splitlines():
                if ".service" in line:
                    add_row(rows, "persist:systemd", "user", "", line.strip(), "INFO")
