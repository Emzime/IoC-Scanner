# scanner/core/win.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import json, csv, os, subprocess

from pathlib import Path
from typing import Dict, List
from scanner.utils import IS_WIN, run_capture_ext, looks_user_or_temp
from scanner.core.common import add_row
from scanner.refs.miners import SUSPICIOUS_CLI_REGEX

# refs/publishers est optionnel : si absent, on tombe sur une liste vide
try:
    from scanner.refs.publishers import TRUSTED_PUBLISHERS  # type: ignore[import]
except ImportError:
    TRUSTED_PUBLISHERS: list[str] = []

def resolve_shortcut_target_windows(shortcut_path: os.PathLike[str] | str) -> str | None:
    if not IS_WIN:
        return None
    try:
        path_str = str(shortcut_path).replace("'", "''")
        ps_cmd = (
            "$sh=New-Object -ComObject WScript.Shell; "
            f"$sc=$sh.CreateShortcut('{path_str}'); "
            "if($sc -and $sc.TargetPath){[Console]::Out.Write($sc.TargetPath)}"
        )
        code, out, _ = run_capture_ext(["powershell", "-NoProfile", "-Command", ps_cmd])
        out = (out or "").strip()
        return out if code == 0 and out else None
    except (OSError, PermissionError, subprocess.SubprocessError):
        return None

def scan_windows_startup_folders(rows: List[Dict[str, str]], *, log=None) -> None:
    if not IS_WIN:
        return
    paths = [
        Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
        Path(os.environ.get("PROGRAMDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
    ]
    ext = {".lnk", ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".js"}
    for p in paths:
        try:
            if p and p.exists():
                if log:
                    log(f"[i] Startup folder: {p}")
                for f in p.iterdir():
                    if f.is_file() and f.suffix.lower() in ext:
                        sev = "MEDIUM"
                        target = resolve_shortcut_target_windows(f) if f.suffix.lower() == ".lnk" else None
                        target_or_self = target or str(f)
                        if looks_user_or_temp(target_or_self):
                            sev = "HIGH"
                        add_row(rows, "persist:startup", str(p), f.name, str(f), sev)
        except (OSError, PermissionError):
            if log:
                log(f"[!] Accès impossible: {p}")

def scan_windows_services(rows: List[Dict[str, str]], *, log=None) -> None:
    if not IS_WIN:
        return

    def handle(reader):
        for rec in reader:
            name = (rec.get("Name") or "").strip()
            display = (rec.get("DisplayName") or "").strip()
            path = (rec.get("PathName") or "").strip()
            start_mode = (rec.get("StartMode") or "").strip()
            state = (rec.get("State") or "").strip()
            if not name:
                continue
            exe = path
            if exe.startswith('"'):
                exe = exe.split('"', 2)[1] if '"' in exe[1:] else exe
            else:
                exe = exe.split(" ", 1)[0]
            if start_mode.lower().startswith("auto"):
                sev = "INFO"
                low = (exe or path).lower()
                if low and not (low.startswith(r"c:\windows") or low.startswith(r"c:\program files")):
                    sev = "MEDIUM"
                    if any(x in low for x in ["\\appdata\\", "\\users\\", "\\temp\\"]):
                        sev = "HIGH"
                add_row(rows, "win:service", name, f"{display} [{state}|{start_mode}]", path or "(no path)", sev)

    code, out, _ = run_capture_ext(["wmic", "service", "get", "Name,DisplayName,StartMode,State,PathName", "/FORMAT:CSV"])
    if code == 0 and out:
        if log:
            log("[v] Services via WMIC")
        rdr = csv.DictReader(out.splitlines())
        handle(rdr)
        return

    ps_cmd = [
        "powershell", "-NoProfile", "-Command",
        "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,StartMode,State,PathName | ConvertTo-Csv -NoTypeInformation"
    ]
    code, out, _ = run_capture_ext(ps_cmd)
    if code == 0 and out:
        if log:
            log("[v] Services via CIM")
        rdr = csv.DictReader(out.splitlines())
        handle(rdr)

def scan_windows_defender_exclusions(rows: List[Dict[str, str]], *, log=None) -> None:
    if not IS_WIN:
        return
    try:
        import winreg
    except ImportError:
        return
    base = r"SOFTWARE\Microsoft\Windows Defender\Exclusions"
    for hive, sub in [(winreg.HKEY_LOCAL_MACHINE, base)]:
        try:
            with winreg.OpenKey(hive, sub) as h:
                i = 0
                while True:
                    try:
                        name = winreg.EnumKey(h, i); i += 1
                        with winreg.OpenKey(h, name) as h2:
                            j = 0
                            while True:
                                try:
                                    v_name, vdata, _ = winreg.EnumValue(h2, j); j += 1
                                    add_row(rows, "win:defender:excl", name, v_name, str(vdata), "MEDIUM")
                                except OSError:
                                    break
                    except OSError:
                        break
        except OSError:
            if log:
                log(f"[!] Lecture registre impossible: {sub}")

def scan_windows_proxy(rows: List[Dict[str, str]], *, log=None) -> None:
    if not IS_WIN:
        return
    try:
        import winreg
    except ImportError:
        return
    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as h:
            try:
                proxy_enable, _ = winreg.QueryValueEx(h, "ProxyEnable")
            except OSError:
                proxy_enable = 0
            try:
                proxy_server, _ = winreg.QueryValueEx(h, "ProxyServer")
            except OSError:
                proxy_server = ""
            if proxy_enable:
                add_row(rows, "win:proxy", "HKCU", "ProxyEnable", str(proxy_enable), "MEDIUM")
                add_row(rows, "win:proxy", "HKCU", "ProxyServer", str(proxy_server), "MEDIUM")
    except OSError:
        if log:
            log(f"[!] Lecture registre impossible: HKCU\\{path}")

def scan_wmi_persistence(rows: List[Dict[str, str]], *, log=None) -> None:
    if not IS_WIN:
        return

    # On passe par PowerShell / CIM (plus fiable que WMIC)
    ps = [
        "powershell", "-NoProfile", "-Command",
        r"$f = Get-CimInstance -Namespace root\subscription __EventFilter | "
        r"Select-Object Name,Query,CreatorSID,__RELPATH;"
        r"$c = Get-CimInstance -Namespace root\subscription __EventConsumer | "
        r"Select-Object __CLASS,Name,CommandLineTemplate,ScriptText,ScriptingEngine,__RELPATH;"
        r"$b = Get-CimInstance -Namespace root\subscription __FilterToConsumerBinding | "
        r"Select-Object Filter,Consumer;"
        r"$o = [PSCustomObject]@{Filters=$f;Consumers=$c;Bindings=$b};"
        r"$o | ConvertTo-Json -Depth 5"
    ]
    code, out, err = run_capture_ext(ps)
    if code != 0 or not out:
        if log:
            log(f"[v] WMI: commande PowerShell échouée ({err.strip() if err else 'no output'})")
        return

    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        if log:
            log("[v] WMI: JSON illisible")
        return

    filters = { (f.get("Name") or f.get("__RELPATH") or ""): f for f in (data.get("Filters") or []) if isinstance(f, dict) }
    consumers = { (c.get("Name") or c.get("__RELPATH") or ""): c for c in (data.get("Consumers") or []) if isinstance(c, dict) }

    # Normaliser les clés pour faire matcher Name vs __RELPATH dans les Bindings
    def matches(key: str, target: str) -> bool:
        k = (key or "").lower()
        t = (target or "").lower()
        return k == t or k in t or t in k

    # Construit une liste (Filter, Consumer)
    bindings: list[tuple[dict, dict]] = []
    for b in (data.get("Bindings") or []):
        if not isinstance(b, dict):
            continue
        f_ref = (b.get("Filter") or "").split(":", 1)[-1]  # e.g. \\.\root\subscription:__EventFilter.Name="X"
        c_ref = (b.get("Consumer") or "").split(":", 1)[-1]
        f_obj = next((v for k, v in filters.items() if matches(k, f_ref)), None)
        c_obj = next((v for k, v in consumers.items() if matches(k, c_ref)), None)
        if f_obj and c_obj:
            bindings.append((f_obj, c_obj))

    # Si aucun binding → rien à signaler (on ne liste pas les filtres isolés).
    if not bindings:
        return

    for f_obj, c_obj in bindings:
        f_name = f_obj.get("Name") or "(unnamed)"
        f_query = (f_obj.get("Query") or "").strip()
        c_class = (c_obj.get("__CLASS") or "").strip()
        c_name = (c_obj.get("Name") or "").strip()
        cmd = (c_obj.get("CommandLineTemplate") or c_obj.get("ScriptText") or "").strip()

        # Sévérité : HIGH si exécution commande/script, sinon MEDIUM
        sev = "HIGH" if c_class in {"CommandLineEventConsumer", "ActiveScriptEventConsumer"} else "MEDIUM"

        item = f"{f_name} → {c_class}:{c_name or '(anon)'}"
        detail = f"Query={f_query}" + (f" | Payload={cmd}" if cmd else "")
        add_row(rows, "win:wmi:binding", "root\\subscription", item, detail, sev)

def scan_persistence(rows: List[Dict[str, str]], *, log=None, verbose: bool=False) -> None:
    code, out, _ = run_capture_ext(["schtasks", "/Query", "/V", "/FO", "CSV"])
    if code != 0 or not out:
        return
    try:
        sample = "\n".join(out.splitlines()[:10])
        dialect = csv.Sniffer().sniff(sample)
        deli = dialect.delimiter
    except csv.Error:
        deli = ','
    reader = csv.DictReader(out.splitlines(), delimiter=deli)

    def pick(d: Dict[str, str], *alts: str) -> str:
        for k in alts:
            if k in d:
                return d[k] or ""
        d_lower = {k.lower(): k for k in d.keys()}
        for want in alts:
            w = want.lower()
            for kl, korig in d_lower.items():
                if w in kl:
                    return d[korig] or ""
        return ""

    if log and verbose:
        log("[v] Tâches planifiées (persistences)")

    for rec in reader:
        name = pick(rec, "TaskName", "Task Name", "Nom de la tâche").strip()
        action = pick(rec, "Task To Run", "Action", "Actions", "Tâche à exécuter").strip()
        next_run = pick(
            rec,
            "Next Run Time",
            "Prochaine heure d'exécution",
            "Heure de la prochaine exécution",
            "Prochaine exécution",
        ).strip()
        if not (name or action or next_run):
            continue
        severity = "MEDIUM" if (action and SUSPICIOUS_CLI_REGEX.search(action)) else "INFO"
        if log and verbose and (severity != "INFO"):
            log(f"[~] Tâche potentiellement suspecte: {name} → {action}")
        add_row(rows, "persist:task", name, next_run, action, severity)
