# scanner/core/mac.py
# -*- coding: utf-8 -*-
from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from scanner.utils import IS_MAC, run_capture_ext
from scanner.core.common import add_row

def scan_macos_launch_globals(rows: List[Dict[str, str]], *, log=None) -> None:
    if not IS_MAC:
        return
    for p in [Path("/Library/LaunchDaemons"), Path("/Library/LaunchAgents")]:
        try:
            if p.exists():
                if log:
                    log(f"[v] Parcours {p}")
                for f in p.glob("*.plist"):
                    add_row(rows, "mac:launch", str(p), f.name, str(f), "INFO")
        except OSError:
            if log:
                log(f"[!] Accès impossible: {p}")

def scan_macos_login_items(rows: List[Dict[str, str]], *, log=None) -> None:
    if not IS_MAC:
        return
    code, out, _ = run_capture_ext(['osascript', '-e',
                                    'tell application "System Events" to get the name of every login item'])
    if code == 0 and out:
        if log:
            log("[v] Login Items récupérés")
        items = [x.strip() for x in out.strip().split(",") if x.strip()]
        for it in items:
            add_row(rows, "mac:loginitem", "", it, it, "INFO")

def scan_macos_profiles(rows: List[Dict[str, str]], *, log=None) -> None:
    if not IS_MAC:
        return
    code, out, _ = run_capture_ext(["profiles", "-P"])
    if code == 0 and out:
        if log:
            log("[v] Profiles listés")
        for line in out.splitlines():
            s = line.strip()
            if s:
                add_row(rows, "mac:profiles", "", "", s, "INFO")

def scan_persistence(rows: List[Dict[str, str]], *, log=None, verbose: bool=False) -> None:
    if not IS_MAC:
        return
    user_agents = Path.home() / "Library" / "LaunchAgents"
    if user_agents.exists():
        if log and verbose:
            log(f"[v] LaunchAgents utilisateur: {user_agents}")
        for plist in user_agents.glob("*.plist"):
            add_row(rows, "persist:launchagent", str(user_agents), plist.name, str(plist), "INFO")
    code, out, _ = run_capture_ext(["launchctl", "list"])
    if code == 0 and out:
        if log and verbose:
            log("[v] launchctl list")
        for line in out.splitlines():
            if line and not line.lower().startswith("pid"):
                add_row(rows, "persist:launchctl", "", "", line, "INFO")
