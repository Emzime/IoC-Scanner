# scanner/core/common.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import csv, json, os, platform, re, threading

from datetime import datetime
from operator import itemgetter
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Optional

# --- imports: absolus d'abord, puis repli relatif ---
try:
    # préférés (fonctionnent si le paquet 'scanner' est visible sur sys.path)
    from scanner.utils import (
        IS_WIN, IS_MAC, IS_LIN, EXEC_TIMEOUT,
        run_capture_ext, which, read_json, sha256_of,
        looks_user_or_temp, list_processes,
        write_csv, write_json,
    )
    from scanner.refs.packages import BAD_PACKAGES, TARGETS, SYSUPDATER_NAMES
    from scanner.refs.miners import (
        MINER_FILE_HINTS, MINER_PROC_HINTS,
        SUSPICIOUS_CLI_REGEX, SUSPICIOUS_SCRIPT_PATTERNS,
    )
except ImportError:  # fallback si importé comme sous-module relatif
    from scanner.utils import (
        IS_WIN, IS_MAC, IS_LIN, EXEC_TIMEOUT,
        run_capture_ext, which, read_json, sha256_of,
        looks_user_or_temp, list_processes,
        write_csv, write_json,
    )
    from scanner.refs.packages import BAD_PACKAGES, TARGETS, SYSUPDATER_NAMES
    from scanner.refs.miners import (
        MINER_FILE_HINTS, MINER_PROC_HINTS,
        SUSPICIOUS_CLI_REGEX, SUSPICIOUS_SCRIPT_PATTERNS,
    )

def add_row(rows: List[Dict[str, str]], category: str, project: str, item: str, detail: str, severity: str) -> None:
    rows.append({
        "Category": category,
        "Project": project,
        "Item": item,
        "Detail": detail,
        "Severity": severity,
    })

def is_compromised(name: str, version: str) -> bool:
    return name in BAD_PACKAGES and version in BAD_PACKAGES[name]

def walk_package_tree(
        node: Dict[str, Any], current_name: str, path_stack: List[str],
        rows: List[Dict[str, str]], project: str, only_risk: bool,
) -> None:
    if not isinstance(node, dict):
        return
    version = node.get("version")
    if current_name and version and current_name in TARGETS:
        compromised = is_compromised(current_name, version)
        if (not only_risk) or compromised:
            status = "À RISQUE" if compromised else "OK"
            severity = "HIGH" if compromised else "INFO"
            where = " > ".join(path_stack)
            add_row(rows, "npm:packages", project, f"{current_name}@{version} [{status}]", where, severity)

    dependencies = node.get("dependencies") or {}
    for depname, depnode in dependencies.items():
        walk_package_tree(depnode, depname, path_stack + [depname], rows, project, only_risk)

def _should_stop(cancel: Optional[threading.Event]) -> bool:
    return bool(cancel and cancel.is_set())

def _depth_of(dirpath: str, root: Path) -> int:
    try:
        rel = Path(dirpath).resolve().relative_to(root.resolve())
        return len(rel.parts)
    except (OSError, ValueError, RuntimeError):
        return max(0, len(Path(dirpath).parts) - len(root.parts))

def scan_sysupdater_in_dir(base: Path, project_tag: str, rows: List[Dict[str, str]],
                           *, log_fn=None, verbose: bool = False, cancel: Optional[threading.Event] = None) -> None:
    for dirpath, _, files in os.walk(base, topdown=True):
        if _should_stop(cancel):
            return
        if verbose and log_fn:
            log_fn(f"[v]       scan IoC: {dirpath}")
        for filename in files:
            if _should_stop(cancel):
                return
            if filename.lower() in SYSUPDATER_NAMES:
                full = Path(dirpath) / filename
                digest = sha256_of(full)
                detail = f"{full} (SHA256={digest})" if digest else str(full)
                add_row(rows, "IoC:sysupdater", project_tag, filename, detail, "HIGH")

def scan_npm_project(
        proj_dir: Path, rows: List[Dict[str, str]], only_risk: bool = False,
        check_sysupdater: bool = True, check_scripts: bool = True, *,
        log_fn=None, verbose: bool = False, cancel: Optional[threading.Event] = None,
) -> None:
    if _should_stop(cancel):
        return

    pkg = proj_dir / "package.json"
    if not pkg.exists():
        return

    if verbose and log_fn:
        log_fn(f"[v]      package.json: {pkg}")

    project = str(proj_dir)

    # --- npm ls (arbre complet) ---
    if which("npm") and not _should_stop(cancel):
        code, out, _ = run_capture_ext(["npm", "ls", "--all", "--json"], cwd=proj_dir)
        if verbose and log_fn:
            log_fn(f"[v]      npm ls (code={code})")
        if out.strip() and code == 0:
            try:
                data = json.loads(out)
                if isinstance(data, dict):  # ✅ durci
                    root_name = data.get("name", "")
                    walk_package_tree(data, root_name, ["root"], rows, project, only_risk)
            except json.JSONDecodeError:
                if log_fn:
                    log_fn("[v]      (parse npm ls JSON échoué)")

    if _should_stop(cancel):
        return

    # --- package-lock.json ---
    lock = proj_dir / "package-lock.json"
    if lock.exists():
        if verbose and log_fn:
            log_fn(f"[v]      package-lock.json: {lock}")
        data = read_json(lock)
        if isinstance(data, dict):  # ✅ durci
            pkgs = data.get("packages")
            if isinstance(pkgs, dict):
                for pkgpath, meta in pkgs.items():
                    if _should_stop(cancel):
                        return
                    if not isinstance(meta, dict):
                        continue
                    name = meta.get("name")
                    version = meta.get("version")
                    if name and version and name in TARGETS:
                        compromised = is_compromised(name, version)
                        if (not only_risk) or compromised:
                            status = "À RISQUE" if compromised else "OK"
                            sev = "HIGH" if compromised else "INFO"
                            add_row(
                                rows, "npm:packages", project,
                                f"{name}@{version} [{status}]", str(pkgpath), sev
                            )
        elif log_fn and verbose:
            log_fn("[v]      (package-lock.json ignoré: pas un objet JSON)")

    if _should_stop(cancel):
        return

    # --- yarn.lock ---
    yarn_lock = proj_dir / "yarn.lock"
    if yarn_lock.exists():
        try:
            txt = yarn_lock.read_text(encoding="utf-8", errors="ignore")
            for name in TARGETS:
                for m in re.finditer(rf"\b{name}@(\d+\.\d+\.\d+)\b", txt):
                    ver = m.group(1)
                    compromised = is_compromised(name, ver)
                    if (not only_risk) or compromised:
                        status = "À RISQUE" if compromised else "OK"
                        sev = "HIGH" if compromised else "INFO"
                        add_row(rows, "npm:packages", project, f"{name}@{ver} [{status}]", "yarn.lock", sev)
        except (OSError, UnicodeError):
            if log_fn:
                log_fn("[!] Lecture yarn.lock impossible")

    # --- pnpm-lock.yaml ---
    pnpm_lock = proj_dir / "pnpm-lock.yaml"
    if pnpm_lock.exists():
        try:
            txt = pnpm_lock.read_text(encoding="utf-8", errors="ignore")
            for name in TARGETS:
                for m in re.finditer(rf"\b{name}@(\d+\.\d+\.\d+)\b", txt):
                    ver = m.group(1)
                    compromised = is_compromised(name, ver)
                    if (not only_risk) or compromised:
                        status = "À RISQUE" if compromised else "OK"
                        sev = "HIGH" if compromised else "INFO"
                        add_row(rows, "npm:packages", project, f"{name}@{ver} [{status}]", "pnpm-lock.yaml", sev)
        except (OSError, UnicodeError):
            if log_fn:
                log_fn("[!] Lecture pnpm-lock.yaml impossible")

    # --- scripts npm (install/postinstall/etc.) ---
    if check_scripts and pkg.exists():
        descriptor = read_json(pkg)
        if isinstance(descriptor, dict) and isinstance(descriptor.get("scripts"), dict):  # ✅ durci
            for script_name, script_cmd in descriptor["scripts"].items():
                if _should_stop(cancel):
                    return
                cmd = str(script_cmd) if script_cmd is not None else ""
                is_install_phase = bool(re.search(r"(postinstall|prepare|install)", script_name, flags=re.I))
                has_suspicious_pattern = any(re.search(pat, cmd, flags=re.I) for pat in SUSPICIOUS_SCRIPT_PATTERNS)
                if is_install_phase or has_suspicious_pattern:
                    add_row(rows, "npm:scripts", project, str(script_name), cmd, "MEDIUM")
                    # Ajoute le chemin du descriptor (package.json) dans l'enregistrement courant
                    rows[-1]["DescriptorPath"] = str(pkg)

                    # .npmrc (local/profil)
        for _rc in [proj_dir / ".npmrc", Path.home() / ".npmrc"]:
            try:
                if _rc.exists() and "ignore-scripts=true" in _rc.read_text(encoding="utf-8", errors="ignore"):
                    add_row(rows, "npm:config", project, "ignore-scripts", str(_rc), "INFO")
            except (OSError, UnicodeError):
                if log_fn:
                    log_fn(f"[!] Lecture impossible: {_rc}")

    # --- IoC sysupdater dans le projet ---
    if check_sysupdater and not _should_stop(cancel):
        if log_fn and verbose:
            log_fn(f"[v]      IoC sysupdater dans {proj_dir}")
        scan_sysupdater_in_dir(proj_dir, project, rows, log_fn=log_fn, verbose=verbose, cancel=cancel)

def scan_projects_under_root(
        root: Path, exclude_names: Iterable[str], rows: List[Dict[str, str]],
        only_risk: bool, check_sysupdater: bool, check_scripts: bool,
        max_depth: int = 6, follow_links: bool = False, *,
        log_fn=None, verbose: bool = False, cancel: Optional[threading.Event] = None,
) -> None:
    exclusions = {name.strip().lower() for name in exclude_names if name and name.strip()}
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=follow_links):
        if _should_stop(cancel):
            return
        if max_depth is not None and _depth_of(dirpath, root) > max_depth:
            dirnames[:] = []
            continue
        if verbose and log_fn:
            log_fn(f"[v] Dir: {dirpath}")

        pruned = []
        for d in dirnames:
            dl = d.lower()

            # exclusions générales
            if dl in exclusions or dl in {"node_modules", ".git", ".hg", ".svn", ".cache", "__pycache__"}:
                # mais cas spécial : extensions doit être ignoré uniquement sous.vscode
                if dl == "extensions" and Path(dirpath).name.lower() != ".vscode":
                    pruned.append(d)
                continue

            # exclusion spécifique : extensions sous .vscode
            if dl == "extensions" and Path(dirpath).name.lower() == ".vscode":
                if verbose and log_fn:
                    log_fn(f"[v] Ignoré: {Path(dirpath) / d}")
                continue

            pruned.append(d)

        dirnames[:] = pruned

        # détection de projet npm
        if "package.json" in (name.lower() for name in filenames):
            proj_dir = Path(dirpath)
            if log_fn:
                log_fn(f"[v]   → Projet npm: {proj_dir}")
            scan_npm_project(
                proj_dir, rows, only_risk=only_risk, check_sysupdater=check_sysupdater,
                check_scripts=check_scripts, log_fn=log_fn, verbose=verbose, cancel=cancel,
            )

def scan_hosts_file(rows: List[Dict[str, str]], *, log=None) -> None:
    paths = [Path(r"C:\Windows\System32\drivers\etc\hosts")] if IS_WIN else [Path("/etc/hosts")]
    for p in paths:
        try:
            if p.exists():
                if log:
                    log(f"[i] Vérification hosts: {p}")
                for i, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    if " localhost" in s and s.startswith(("127.0.0.1", "::1")):
                        continue
                    add_row(rows, "net:hosts", str(p), f"ligne {i}", s, "MEDIUM")
        except (OSError, UnicodeError):
            if log:
                log(f"[!] Lecture impossible: {p}")

def scan_listening_ports(rows: List[Dict[str, str]]) -> None:
    suspicious_ports = {3333, 4444, 5555, 7777, 14444}

    if IS_WIN:
        # --- Build a PID -> Image Name map (once) ---
        pid_name: dict[int, str] = {}

        code_t, out_t, _ = run_capture_ext(["tasklist", "/FO", "CSV", "/NH"])
        lines: list[str] = out_t.splitlines() if (code_t == 0 and out_t) else []

        if lines:
            # detect delimiter (',' in en-US, ';' in some locales)
            try:
                sample = "\n".join(lines[:5]) or ","
                deli = csv.Sniffer().sniff(sample).delimiter
            except csv.Error:
                deli = ","

            rdr = csv.DictReader(lines, delimiter=deli)
            for rec in rdr:
                raw_name = (rec.get("Image Name") or rec.get("Nom de l'image") or "").strip()
                raw_pid = (rec.get("PID") or rec.get("Identificateur de processus") or "").strip()
                if not (raw_name and raw_pid):
                    continue
                try:
                    pid_name[int(raw_pid)] = raw_name
                except (ValueError, TypeError):
                    continue

        code, out, _ = run_capture_ext(["netstat", "-ano"])
        if code != 0 or not out:
            return

        for raw in out.splitlines():
            s = raw.strip()
            if not s or " LISTENING " not in s or not s.upper().startswith("TCP"):
                continue

            parts = re.split(r"\s+", s)
            if len(parts) < 5:
                continue

            local_addr = parts[1]

            # PID is last column on Windows
            try:
                pid = int(parts[-1])
            except (ValueError, TypeError):
                pid = None

            port: Optional[int] = None
            if ":" in local_addr:
                try:
                    port = int(local_addr.rsplit(":", 1)[-1])
                except (ValueError, TypeError):
                    port = None

            sev = "HIGH" if (port in suspicious_ports) else "MEDIUM"
            proc = pid_name.get(pid, "").strip() if pid is not None else ""

            # Keep full netstat line, append PID/name tag for convenience
            detail = s
            if pid is not None:
                tag = f" | PID={pid}" + (f" ({proc})" if proc else "")
                detail = f"{s}{tag}"

            add_row(rows, "net:listen", "", (f"port {port}" if port else "socket"), detail, sev)
        return

    # --- Linux/macOS paths unchanged ---
    code, out, _ = run_capture_ext(["ss", "-lntup"])
    if code == 0 and out:
        for raw in out.splitlines():
            s = raw.strip()
            if not s:
                continue
            ms = re.findall(r":(\d{2,5})(?:\s|$)", s)
            port = int(ms[-1]) if ms else None
            sev = "HIGH" if (port in suspicious_ports) else "MEDIUM"
            add_row(rows, "net:listen", "", (f"port {port}" if port else "socket"), s, sev)
        return

    code2, out2, _ = run_capture_ext(["lsof", "-i", "-P", "-n"])
    if code2 != 0 or not out2:
        return
    for raw in out2.splitlines():
        s = raw.strip()
        if not s or "LISTEN" not in s.upper():
            continue
        ms = re.findall(r":(\d{2,5})(?:\s|$)", s)
        port = int(ms[-1]) if ms else None
        sev = "HIGH" if (port in suspicious_ports) else "MEDIUM"
        add_row(rows, "net:listen", "", (f"port {port}" if port else "socket"), s, sev)

def scan_shell_profiles(rows: List[Dict[str, str]], *, log=None) -> None:
    for name in [".bashrc", ".zshrc", ".profile", ".bash_profile"]:
        p = Path.home() / name
        try:
            if p.exists():
                if log:
                    log(f"[v] Profil: {p}")
                txt = p.read_text(encoding="utf-8", errors="ignore")
                for i, line in enumerate(txt.splitlines(), start=1):
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    if any(re.search(pat, s, flags=re.I) for pat in SUSPICIOUS_SCRIPT_PATTERNS):
                        add_row(rows, "shell:profile", str(p), f"ligne {i}", s, "MEDIUM")
        except (OSError, UnicodeError):
            if log:
                log(f"[!] Lecture impossible: {p}")

def scan_sysupdater_global(
        root: Path, exclude_names: Iterable[str], rows: List[Dict[str, str]], max_depth: int = 12, *,
        log_fn=None, verbose: bool = False, cancel: Optional[threading.Event] = None,
) -> None:
    exclusions = {name.lower() for name in exclude_names}
    for dirpath, dirnames, files in os.walk(root, topdown=True):
        if _should_stop(cancel):
            return
        if max_depth is not None and _depth_of(dirpath, root) > max_depth:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d.lower() not in exclusions]
        if verbose and log_fn:
            log_fn(f"[v] IoC global: {dirpath}")
        for filename in files:
            if _should_stop(cancel):
                return
            if filename.lower() in SYSUPDATER_NAMES:
                full = Path(dirpath) / filename
                digest = sha256_of(full)
                detail = f"{full} (SHA256={digest})" if digest else str(full)
                add_row(rows, "IoC:sysupdater", str(root), filename, detail, "HIGH")

def scan_miner_files(
        root: Path, exclude_names: Iterable[str], rows: List[Dict[str, str]], max_depth: int = 8, *,
        log_fn=None, verbose: bool = False, cancel: Optional[threading.Event] = None,
) -> None:
    exclusions = {name.lower() for name in exclude_names}
    compiled = [re.compile(rx, re.I) for rx in MINER_FILE_HINTS]
    for dirpath, dirnames, files in os.walk(root, topdown=True):
        if _should_stop(cancel):
            return
        if max_depth is not None and _depth_of(dirpath, root) > max_depth:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d.lower() not in exclusions]
        if verbose and log_fn:
            log_fn(f"[v] miners: {dirpath}")
        for filename in files:
            if _should_stop(cancel):
                return
            if any(rx.search(filename) for rx in compiled):
                full = Path(dirpath) / filename
                digest = sha256_of(full)
                detail = f"{full} (SHA256={digest})" if digest else str(full)
                add_row(rows, "miner:file", str(root), filename, detail, "HIGH")

def scan_miner_processes(rows: List[Dict[str, str]], *, log=None, verbose: bool = False) -> None:
    name_rx = [re.compile(pattern, re.I) for pattern in MINER_PROC_HINTS]
    for name, pid, cmd, _ in list_processes():
        low = (name or "").lower()
        looks_like_miner = any(rx.search(low) for rx in name_rx)
        suspicious_cmd = bool(cmd and SUSPICIOUS_CLI_REGEX.search(cmd))
        if looks_like_miner or suspicious_cmd:
            severity = "HIGH" if suspicious_cmd else "MEDIUM"
            detail = f"PID={pid}; Cmd={cmd[:500]}"
            if log and verbose:
                log(f"[+] Processus suspect: {name} (PID {pid})")
            add_row(rows, "miner:process", "", name, detail, severity)

def run_scan_core(
        root: Path, exclude_names: Iterable[str], options: SimpleNamespace, *,
        log_fn=None, cancel: Optional[threading.Event] = None,
):
    def log(message: str) -> None:
        if log_fn:
            log_fn(str(message))

    rows: List[Dict[str, str]] = []
    log(f"[i] Début du scan — {datetime.now().isoformat(timespec='seconds')}")
    log(f"[i] Racine : {root}")
    log(f"[i] Exclusions : {', '.join(exclude_names) if exclude_names else '(aucune)'}")
    log(f"[i] Profondeur max : {options.max_depth} | Follow links: {options.follow_links}")
    log(f"[i] OS : {platform.platform()} | Python {platform.python_version()}")

    from . import win as _win
    from . import mac as _mac
    from . import linux as _lin

    try:
        if not _should_stop(cancel):
            if not options.no_npm:
                log("[i] Étape: détection de projets npm…")
                scan_projects_under_root(
                    root, exclude_names, rows, options.only_risk, options.sysupdater_project,
                    not options.no_scripts, max_depth=options.max_depth, follow_links=options.follow_links,
                    log_fn=log, verbose=getattr(options, "verbose", False), cancel=cancel,
                )
            elif options.sysupdater_project:
                log("[i] Étape: recherche .sysupdater dans projets…")
                scan_projects_under_root(
                    root, exclude_names, rows, False, True, False,
                    max_depth=options.max_depth, follow_links=options.follow_links,
                    log_fn=log, verbose=getattr(options, "verbose", False), cancel=cancel,
                )

        if not _should_stop(cancel) and options.sysupdater_global:
            log("[i] Étape: recherche .sysupdater globale…")
            scan_sysupdater_global(root, exclude_names, rows, max_depth=max(options.max_depth, 8),
                                   log_fn=log, verbose=getattr(options, "verbose", False), cancel=cancel)

        if not _should_stop(cancel) and options.miners:
            log("[i] Étape: IoC mineurs (fichiers)…")
            scan_miner_files(root, exclude_names, rows, max_depth=max(options.max_depth, 6),
                             log_fn=log, verbose=getattr(options, "verbose", False), cancel=cancel)
            if not _should_stop(cancel):
                log("[i] Étape: IoC mineurs (process)…")
                scan_miner_processes(rows, log=log, verbose=getattr(options, "verbose", False))

        if not _should_stop(cancel) and options.persistence:
            if IS_WIN:
                log("[i] Étape: persistance OS (Windows)…")
                _win.scan_persistence(rows, log=log, verbose=getattr(options, "verbose", False))
            elif IS_MAC:
                log("[i] Étape: persistance OS (macOS)…")
                _mac.scan_persistence(rows, log=log, verbose=getattr(options, "verbose", False))
            else:
                log("[i] Étape: persistance OS (Linux)…")
                _lin.scan_persistence(rows, log=log, verbose=getattr(options, "verbose", False))

        if not _should_stop(cancel) and getattr(options, "hosts", False):
            log("[i] Étape: fichier hosts…")
            scan_hosts_file(rows, log=log)

        if not _should_stop(cancel) and getattr(options, "net_listen", False):
            log("[i] Étape: ports en écoute…")
            scan_listening_ports(rows)

        if not _should_stop(cancel) and getattr(options, "shell_profiles", False):
            log("[i] Étape: profils shell…")
            scan_shell_profiles(rows, log=log)

        if IS_WIN and not _should_stop(cancel) and getattr(options, "startup", False):
            log("[i] Étape: Startup folders (Windows)…")
            _win.scan_windows_startup_folders(rows, log=log)

        if IS_WIN and not _should_stop(cancel) and getattr(options, "services", False):
            log("[i] Étape: Services (Auto)…")
            _win.scan_windows_services(rows, log=log)

        if IS_WIN and not _should_stop(cancel) and getattr(options, "defender_exclusions", False):
            log("[i] Étape: Defender exclusions…")
            _win.scan_windows_defender_exclusions(rows, log=log)

        if IS_WIN and not _should_stop(cancel) and getattr(options, "proxy", False):
            log("[i] Étape: Proxy système…")
            _win.scan_windows_proxy(rows, log=log)

        if IS_WIN and not _should_stop(cancel) and getattr(options, "wmi", False):
            log("[i] Étape: WMI persistence…")
            _win.scan_wmi_persistence(rows, log=log)

        if IS_MAC and not _should_stop(cancel) and getattr(options, "launch_globals", False):
            log("[i] Étape: LaunchDaemons/Agents (globaux)…")
            _mac.scan_macos_launch_globals(rows, log=log)

        if IS_MAC and not _should_stop(cancel) and getattr(options, "login_items", False):
            log("[i] Étape: Login Items…")
            _mac.scan_macos_login_items(rows, log=log)

        if IS_MAC and not _should_stop(cancel) and getattr(options, "profiles", False):
            log("[i] Étape: Profiles (macOS)…")
            _mac.scan_macos_profiles(rows, log=log)

        if IS_LIN and not _should_stop(cancel) and getattr(options, "cron_system", False):
            log("[i] Étape: Cron système…")
            _lin.scan_linux_cron_system(rows, log=log)

        if IS_LIN and not _should_stop(cancel) and getattr(options, "systemd_system", False):
            log("[i] Étape: systemd (système)…")
            _lin.scan_systemd_system(rows, log=log)

        if IS_LIN and not _should_stop(cancel) and getattr(options, "ld_preload", False):
            log("[i] Étape: /etc/ld.so.preload…")
            _lin.scan_ld_preload(rows, log=log)

        if IS_LIN and not _should_stop(cancel) and getattr(options, "suid", False):
            log("[i] Étape: SUID/SGID…")
            _lin.scan_suid_sgid(rows, log=log)

        if IS_LIN and not _should_stop(cancel) and getattr(options, "path_world_writable", False):
            log("[i] Étape: PATH world-writable…")
            _lin.scan_path_world_writable(rows, log=log)

    except KeyboardInterrupt:
        log("[!] Scan interrompu par l'utilisateur — résultats partiels conservés.")

    rows.sort(key=itemgetter("Category", "Project", "Item", "Detail"))
    if getattr(options, "csv", None):
        write_csv(rows, options.csv, delimiter=options.delimiter)
        log(f"[✓] CSV écrit : {options.csv}")
    if getattr(options, "json", None):
        write_json(rows, options.json)
        log(f"[✓] JSON écrit : {options.json}")

    nb_risk = sum(1 for r in rows if r["Severity"] == "HIGH")
    nb_total = len(rows)
    if _should_stop(cancel):
        log(f"[i] Fin anticipée (arrêt demandé). Total lignes: {nb_total} | À risque (HIGH): {nb_risk}")
    else:
        log(f"[i] Fin du scan. Total lignes: {nb_total} | À risque (HIGH): {nb_risk}")
    return rows, {"total": nb_total, "high": nb_risk}
