# scanner/main.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse, os, sys

from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from scanner.core import run_scan_core
from scanner.gui import launch_gui, system_can_use_gui
from scanner import utils as _u
from scanner.refs.labels import SEVERITY_LABEL
from scanner.utils import (
    get_app_name, get_default_root, default_exclude_csv, default_csv_delimiter,
)


def main() -> None:
    default_root = get_default_root()

    parser = argparse.ArgumentParser(
        description=f"{get_app_name()} — npm / IoC / persistance (lecture seule)"
    )
    parser.add_argument("-r", "--root", default=default_root, help="Racine à scanner")
    parser.add_argument(
        "-x", "--exclude", default=default_exclude_csv(),
        help="Dossiers à exclure (séparés par des virgules)"
    )
    parser.add_argument("--no-npm", action="store_true")
    parser.add_argument("--only-risk", action="store_true")
    parser.add_argument("--no-scripts", action="store_true")
    parser.add_argument("--sysupdater-project", action="store_true")
    parser.add_argument("--sysupdater-global", action="store_true")
    parser.add_argument("--miners", action="store_true")
    parser.add_argument("--persistence", action="store_true")
    parser.add_argument("--hosts", action="store_true")
    parser.add_argument("--net-listen", action="store_true")
    parser.add_argument("--shell-profiles", action="store_true")
    parser.add_argument("--startup", action="store_true")
    parser.add_argument("--services", action="store_true")
    parser.add_argument("--defender-exclusions", action="store_true")
    parser.add_argument("--proxy", action="store_true")
    parser.add_argument("--wmi", action="store_true")
    parser.add_argument("--launch-globals", action="store_true")
    parser.add_argument("--login-items", action="store_true")
    parser.add_argument("--profiles", action="store_true")
    parser.add_argument("--cron-system", action="store_true")
    parser.add_argument("--systemd-system", action="store_true")
    parser.add_argument("--ld-preload", action="store_true")
    parser.add_argument("--suid", action="store_true")
    parser.add_argument("--path-world-writable", action="store_true")

    parser.add_argument("--csv", help="Chemin CSV de sortie")
    parser.add_argument("--json", help="Chemin JSON de sortie")
    parser.add_argument("--delimiter", default=None, help="Délimiteur CSV (par défaut culturel)")
    parser.add_argument("--max-depth", type=int, default=6)
    parser.add_argument("--follow-links", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--gui", action="store_true")
    parser.add_argument("--exec-timeout", type=int, default=60)

    args = parser.parse_args()

    # Régler le timeout global des commandes externes
    _u.EXEC_TIMEOUT = max(1, int(args.exec_timeout or 60))

    # Mode GUI si demandé ou si lancé sans arguments et qu’un affichage est disponible
    if args.gui or (len(sys.argv) == 1 and system_can_use_gui()):
        launch_gui()
        return

    root = Path(args.root).resolve()
    exclude = [name.strip() for name in (args.exclude or "").split(",") if name.strip()]
    cli_deli = args.delimiter if args.delimiter is not None else default_csv_delimiter()

    print(f"[i] Début du scan — {datetime.now().isoformat(timespec='seconds')}")
    print(f"[i] Racine : {root}")
    print(f"[i] Exclusions : {', '.join(exclude) if exclude else '(aucune)'}")
    print(f"[i] Profondeur max : {args.max_depth} | Follow links: {args.follow_links}")
    print(f"[i] Python {sys.version.split()[0]}")

    ns = SimpleNamespace(
        no_npm=args.no_npm,
        only_risk=args.only_risk,
        no_scripts=args.no_scripts,
        sysupdater_project=args.sysupdater_project,
        sysupdater_global=args.sysupdater_global,
        miners=args.miners,
        persistence=args.persistence,
        csv=args.csv,
        json=args.json,
        delimiter=cli_deli,
        max_depth=args.max_depth,
        follow_links=args.follow_links,
        verbose=args.verbose,
        hosts=args.hosts,
        net_listen=args.net_listen,
        shell_profiles=args.shell_profiles,
        startup=args.startup,
        services=args.services,
        defender_exclusions=args.defender_exclusions,
        proxy=args.proxy,
        wmi=args.wmi,
        launch_globals=args.launch_globals,
        login_items=args.login_items,
        profiles=args.profiles,
        cron_system=args.cron_system,
        systemd_system=args.systemd_system,
        ld_preload=args.ld_preload,
        suid=args.suid,
        path_world_writable=args.path_world_writable,
        exec_timeout=_u.EXEC_TIMEOUT,
    )

    rows, stats = run_scan_core(root, exclude, ns, log_fn=print, cancel=None)

    print("\n=== RÉSULTATS ===")
    if not rows:
        print("(Aucune détection)")
    else:
        max_display = int(os.environ.get("IOC_MAX_DISPLAY", "300"))
        for row_rec in rows[:max_display]:
            label = SEVERITY_LABEL.get(row_rec.get("Severity", ""), row_rec.get("Severity", ""))
            print(
                f"[{row_rec['Severity']}] ({label}) "
                f"{row_rec['Category']} | {row_rec['Project']} | "
                f"{row_rec['Item']} | {row_rec['Detail']}"
            )
        remaining = len(rows) - max_display
        if remaining > 0:
            print(f"... ({remaining} lignes supplémentaires non affichées)")

    print(f"\nRésumé → Total: {stats['total']} | À risque (HIGH): {stats['high']}")
    print("[i] Fin du scan.")


if __name__ == "__main__":
    main()
