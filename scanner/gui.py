# scanner/gui.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import os, platform, subprocess, threading, sys

from datetime import datetime
from pathlib import Path
from queue import Queue, Empty, Full
from types import SimpleNamespace
from typing import Any, Optional, Callable, cast

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    TK_AVAILABLE = True
except ImportError:  # environnement sans Tk (serveur/headless)
    tk = None  # type: ignore
    ttk = None  # type: ignore
    filedialog = None  # type: ignore
    messagebox = None  # type: ignore
    TK_AVAILABLE = False

# === Importe ce dont l’UI a besoin dans le refactor ===
from scanner.core import run_scan_core
from scanner.utils import (
    IS_WIN, IS_MAC, IS_LIN, EXEC_TIMEOUT,
    get_app_name, get_default_root, get_reports_dir,
    default_output_path, default_exclude_csv, default_csv_delimiter,
)

# --------------------------------------------------------------------
# Utilitaires UI
# --------------------------------------------------------------------

def after0(widget: Any, ms: int, func: Callable[[], None]) -> str:
    return widget.after(ms, func)

class ToolTip:
    """Tooltip simple pour Tk widgets (types mypy-friendly)."""
    def __init__(self, widget: "tk.Widget", text: str, *, delay: int = 500) -> None:
        self.widget = widget
        self.text = text
        self.delay = delay
        self._after_id: Optional[str] = None
        self._tip: Optional["tk.Toplevel"] = None

        widget.bind("<Enter>", self._schedule, add="+")       # type: ignore[arg-type]
        widget.bind("<Leave>", self._hide, add="+")           # type: ignore[arg-type]
        widget.bind("<ButtonPress>", self._hide, add="+")     # type: ignore[arg-type]

    def _schedule(self, _evt: object = None) -> None:
        self._unschedule()
        self._after_id = after0(self.widget, self.delay, self._show)

    def _unschedule(self) -> None:
        if self._after_id:
            try:
                self.widget.after_cancel(self._after_id)
            except tk.TclError:
                pass
            self._after_id = None

    def _show(self) -> None:
        if self._tip or not self.text:
            return
        try:
            x = self.widget.winfo_rootx() + 20
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        except tk.TclError:
            return

        tip = tk.Toplevel(self.widget)
        tip.wm_overrideredirect(True)
        try:
            tip.wm_geometry(f"+{x}+{y}")
        except tk.TclError:
            pass

        lbl = tk.Label(
            tip,
            text=self.text,
            justify="left",
            relief="solid",
            borderwidth=1,
            padx=6,
            pady=4,
            background="#ffffe0",
        )
        lbl.pack()
        self._tip = tip

    def _hide(self, _evt: object = None) -> None:
        self._unschedule()
        if self._tip is not None:
            try:
                self._tip.destroy()
            except tk.TclError:
                pass
            self._tip = None

# --------------------------------------------------------------------
# Détection d’environnement GUI
# --------------------------------------------------------------------

def system_can_use_gui() -> bool:
    if not TK_AVAILABLE:
        return False
    # WSL : on évite par défaut, sauf si display configuré
    if os.environ.get("WSLENV") or os.environ.get("WSL_DISTRO_NAME"):
        return False
    if IS_LIN:
        return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY") or os.environ.get("MIR_SOCKET"))
    return True

# --------------------------------------------------------------------
# Lancement GUI
# --------------------------------------------------------------------

def _resource_path(*parts: str) -> str:
    """
    Retourne un chemin absolu vers une ressource packagée.
    - En binaire PyInstaller onefile : utilise sys._MEIPASS.
    - En dev : relatif au répertoire de ce fichier (scanner/).
    """
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return str(Path(base).joinpath(*parts))
    return str(Path(__file__).resolve().parent.joinpath(*parts))

def launch_gui() -> None:
    if not TK_AVAILABLE:
        print("Tkinter n'est pas disponible. Lance le script sans --gui.")
        return

    app = tk.Tk()
    app.title(f"{get_app_name()}")
    app.minsize(1080, 720)

    # --- Icône fenêtre (Windows: .ico | Linux/macOS: .png) ---
    # Chemins packagés (via --add-data ...;assets / :assets) ET chemins locaux (dev)
    ico_packed = Path(_resource_path("assets", "icon.ico"))
    png_packed = Path(_resource_path("assets", "icon.png"))
    ico_local  = Path(__file__).resolve().parent / "assets" / "icon.ico"
    png_local  = Path(__file__).resolve().parent / "assets" / "icon.png"

    ico = ico_packed if ico_packed.exists() else ico_local
    png = png_packed if png_packed.exists() else png_local

    # Windows → priorité à .ico (barre de titre)
    if IS_WIN and ico.exists():
        try:
            app.iconbitmap(str(ico))
        except tk.TclError:
            # On tentera un fallback PNG plus bas
            pass

    # Tous OS → tenter PNG via iconphoto (fonctionne aussi sous Windows)
    if png.exists():
        try:
            _icon_img = tk.PhotoImage(file=str(png))
            app.iconphoto(True, _icon_img)
            app._icon_img = _icon_img  # éviter le GC
        except tk.TclError:
            # Icône non bloquante : on ignore proprement
            pass

    # --- Vars (défauts intelligents) ---
    root_var = tk.StringVar(value=get_default_root())
    exclude_var = tk.StringVar(value=default_exclude_csv())
    max_depth_var = tk.IntVar(value=6)
    csv_var = tk.StringVar(value="")
    json_var = tk.StringVar(value="")

    follow_links_var = tk.BooleanVar(value=False)
    scan_npm_var = tk.BooleanVar(value=True)
    scripts_var = tk.BooleanVar(value=True)
    only_risk_var = tk.BooleanVar(value=True)
    sys_upd_proj_var = tk.BooleanVar(value=True)
    sys_upd_global_var = tk.BooleanVar(value=False)
    miners_var = tk.BooleanVar(value=False)
    persist_var = tk.BooleanVar(value=True)
    verbose_var = tk.BooleanVar(value=True)

    hosts_var = tk.BooleanVar(value=False)
    net_listen_var = tk.BooleanVar(value=False)
    shell_profiles_var = tk.BooleanVar(value=True)

    # Windows
    startup_var = tk.BooleanVar(value=IS_WIN)
    services_var = tk.BooleanVar(value=IS_WIN)
    defender_var = tk.BooleanVar(value=IS_WIN)
    proxy_var = tk.BooleanVar(value=IS_WIN)
    wmi_var = tk.BooleanVar(value=False)

    # macOS
    launch_globals_var = tk.BooleanVar(value=IS_MAC)
    login_items_var = tk.BooleanVar(value=IS_MAC)
    profiles_var = tk.BooleanVar(value=False)

    # Linux
    cron_system_var = tk.BooleanVar(value=IS_LIN)
    systemd_system_var = tk.BooleanVar(value=IS_LIN)
    ld_preload_var = tk.BooleanVar(value=IS_LIN)
    suid_var = tk.BooleanVar(value=IS_LIN)
    path_ww_var = tk.BooleanVar(value=IS_LIN)

    save_csv_var = tk.BooleanVar(value=True)
    save_json_var = tk.BooleanVar(value=False)
    deli_var = tk.StringVar(value=default_csv_delimiter())

    # --- Layout principal ---
    frm = ttk.Frame(app, padding=12)
    frm.grid(row=0, column=0, sticky="nsew")

    app.columnconfigure(0, weight=1)
    app.rowconfigure(0, weight=1)

    ttk.Label(frm, text="Racine à scanner :").grid(row=0, column=0, sticky=tk.W, padx=2, pady=2)
    ent_root = ttk.Entry(frm, textvariable=root_var, width=70)
    ent_root.grid(row=0, column=1, sticky=tk.E + tk.W, padx=2, pady=2)

    def choose_root() -> None:
        sel = filedialog.askdirectory(initialdir=root_var.get() or str(Path.home()))
        if sel:
            root_var.set(sel)

    ttk.Button(frm, text="Parcourir…", command=choose_root).grid(row=0, column=2, padx=2, pady=2)

    ttk.Label(frm, text="Dossiers à exclure (séparés par des virgules) :").grid(row=1, column=0, sticky=tk.W, padx=2, pady=2)
    ent_excl = ttk.Entry(frm, textvariable=exclude_var, width=70)
    ent_excl.grid(row=1, column=1, columnspan=2, sticky=tk.E + tk.W, padx=2, pady=2)

    ttk.Label(frm, text="Profondeur max :").grid(row=2, column=0, sticky=tk.W, padx=2, pady=2)
    spn_depth = ttk.Spinbox(frm, from_=1, to=32, textvariable=max_depth_var, width=5)
    spn_depth.grid(row=2, column=1, sticky=tk.W, padx=2, pady=2)

    ttk.Label(frm, text="Suivre les liens symboliques :").grid(row=3, column=0, sticky=tk.W, padx=2, pady=(0, 6))
    ttk.Checkbutton(frm, variable=follow_links_var).grid(row=3, column=1, sticky=tk.W, padx=2, pady=(0, 6))

    # ----- Types de scan -----
    box = ttk.LabelFrame(frm, text="Types de scan")
    box.grid(row=4, column=0, columnspan=3, sticky=tk.E + tk.W, padx=2, pady=6)

    def add_opts(frame: "tk.Widget", items: list[tuple[str, tk.BooleanVar, str]], cols: int = 4) -> None:
        r = c = 0
        for text, var, tip in items:
            cb = ttk.Checkbutton(frame, text=text, variable=var)
            cb.grid(row=r, column=c, sticky=tk.W, padx=6, pady=2)
            if tip:
                ToolTip(cb, tip)
            c += 1
            if c >= cols:
                c = 0
                r += 1

    common_items: list[tuple[str, tk.BooleanVar, str]] = [
        ("Scan npm (packages)", scan_npm_var, "Analyse les dépendances installées (node_modules) et leurs versions."),
        ("Analyser scripts npm (install/postinstall…)", scripts_var, "Inspecte les scripts npm susceptibles de s'exécuter à l'installation."),
        ("Seulement paquets à risque", only_risk_var, "N'affiche que les paquets identifiés comme compromis."),
        ("IoC .sysupdater (projets)", sys_upd_proj_var, "Recherche un fichier .sysupdater.dat dans chaque projet."),
        ("IoC .sysupdater (global)", sys_upd_global_var, "Recherche .sysupdater.dat partout sous la racine (plus lent)."),
        ("Persistance (OS)", persist_var, "Liste quelques mécanismes de démarrage automatique selon l'OS."),
        ("Journal détaillé (projets/dirs)", verbose_var, "Affiche chaque répertoire ou projet visité."),
        ("Mineurs (fichiers + process)", miners_var, "Signatures de mineurs : fichiers et processus (xmrig, etc.)."),
        ("Fichier hosts", hosts_var, "Vérifie les entrées potentiellement suspectes du fichier hosts."),
        ("Ports en écoute", net_listen_var, "Liste les sockets/ports ouverts et met en avant certains ports courants."),
        ("Profils shell", shell_profiles_var, "Parcourt ~/.bashrc, ~/.zshrc, etc. et détecte des commandes discutables."),
    ]

    win_items: list[tuple[str, tk.BooleanVar, str]] = []
    mac_items: list[tuple[str, tk.BooleanVar, str]] = []
    lin_items: list[tuple[str, tk.BooleanVar, str]] = []

    if IS_WIN:
        win_items = [
            ("Startup (Windows)", startup_var, "Raccourcis/scripts placés dans les dossiers de démarrage."),
            ("Services Auto (Windows)", services_var, "Services configurés en démarrage automatique."),
            ("Defender exclusions", defender_var, "Chemins exclus de Windows Defender."),
            ("Proxy (Windows)", proxy_var, "Paramètres proxy de l'utilisateur courant."),
            ("WMI persistence", wmi_var, "Abonnements WMI pouvant être utilisés pour la persistance."),
        ]
    if IS_MAC:
        mac_items = [
            ("LaunchDaemons/Agents (macOS)", launch_globals_var, "Liste les LaunchDaemons/Agents globaux."),
            ("Login Items (macOS)", login_items_var, "Éléments ouverts automatiquement à la connexion."),
            ("Profiles (macOS)", profiles_var, "Profils de configuration installés."),
        ]
    if IS_LIN:
        lin_items = [
            ("Cron système (Linux)", cron_system_var, "Tâches cron système /etc/cron.*, /etc/cron.d, etc."),
            ("systemd (système)", systemd_system_var, "Unités systemd au niveau système."),
            ("/etc/ld.so.preload", ld_preload_var, "Fichier LD_PRELOAD (libs injectées globalement)."),
            ("SUID/SGID (Linux)", suid_var, "Binaires avec bit SUID/SGID."),
            ("PATH world-writable (Linux)", path_ww_var, "Répertoires du PATH modifiables par tous."),
        ]

    ttk.Label(box, text="Commun", font=("", 9, "bold")).grid(row=0, column=0, sticky=tk.W, padx=6, pady=(4, 2))
    common_frame = ttk.Frame(box); common_frame.grid(row=1, column=0, sticky=tk.W)
    add_opts(common_frame, common_items, cols=4)
    ttk.Separator(box, orient="horizontal").grid(row=2, column=0, sticky=tk.E + tk.W, padx=4, pady=6)

    if IS_WIN:
        os_title, os_items = "Spécifiques à Windows", win_items
    elif IS_MAC:
        os_title, os_items = "Spécifiques à macOS", mac_items
    elif IS_LIN:
        os_title, os_items = "Spécifiques à Linux", lin_items
    else:
        os_title, os_items = "", []

    if os_items:
        ttk.Label(box, text=os_title, font=("", 9, "bold")).grid(row=3, column=0, sticky=tk.W, padx=6, pady=(0, 2))
        os_frame = ttk.Frame(box); os_frame.grid(row=4, column=0, sticky=tk.W)
        add_opts(os_frame, os_items, cols=(5 if IS_WIN else 4))

    # ----- Sorties -----
    outbox = ttk.LabelFrame(frm, text="Sorties (facultatif)")
    outbox.grid(row=5, column=0, columnspan=3, sticky=tk.E + tk.W, padx=2, pady=6)

    def center_window(win: "tk.Tk | tk.Toplevel", w: int | None = None, h: int | None = None) -> None:
        win.update_idletasks()
        cw = w or win.winfo_width()
        ch = h or win.winfo_height()
        if cw <= 1 or ch <= 1:
            cw = max(cw, win.winfo_reqwidth() + 20)
            ch = max(ch, win.winfo_reqheight() + 20)
        sw = win.winfo_screenwidth(); sh = win.winfo_screenheight()
        x = (sw - cw) // 2; y = (sh - ch) // 2
        win.geometry(f"{cw}x{ch}+{x}+{y}")

    def choose_csv() -> None:
        sel = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile=Path(default_output_path("csv")).name,
            initialdir=str(get_reports_dir()),
            filetypes=[("CSV", ".csv"), ("Tous", "*.*")],
        )
        if sel: csv_var.set(sel)

    def choose_json() -> None:
        sel = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile=Path(default_output_path("json")).name,
            initialdir=str(get_reports_dir()),
            filetypes=[("JSON", ".json"), ("Tous", "*.*")],
        )
        if sel: json_var.set(sel)

    def toggle_csv() -> None:
        if save_csv_var.get():
            if not csv_var.get():
                csv_var.set(default_output_path("csv"))
            if save_json_var.get():
                save_json_var.set(False)
                ent_json.configure(state="disabled"); btn_json.configure(state="disabled")
        ent_csv.configure(state=("normal" if save_csv_var.get() else "disabled"))
        btn_csv.configure(state=("normal" if save_csv_var.get() else "disabled"))

    def toggle_json() -> None:
        if save_json_var.get():
            if not json_var.get():
                json_var.set(default_output_path("json"))
            if save_csv_var.get():
                save_csv_var.set(False)
                ent_csv.configure(state="disabled"); btn_csv.configure(state="disabled")
        ent_json.configure(state=("normal" if save_json_var.get() else "disabled"))
        btn_json.configure(state=("normal" if save_json_var.get() else "disabled"))

    ttk.Checkbutton(outbox, text="CSV", variable=save_csv_var, command=toggle_csv).grid(row=0, column=0, sticky=tk.W, padx=4, pady=2)
    ent_csv = ttk.Entry(outbox, textvariable=csv_var, width=60); ent_csv.grid(row=0, column=1, sticky=tk.E + tk.W, padx=2, pady=2)
    btn_csv = ttk.Button(outbox, text="Parcourir…", command=choose_csv); btn_csv.grid(row=0, column=2, padx=2, pady=2)

    ttk.Checkbutton(outbox, text="JSON", variable=save_json_var, command=toggle_json).grid(row=1, column=0, sticky=tk.W, padx=4, pady=2)
    ent_json = ttk.Entry(outbox, textvariable=json_var, width=60); ent_json.grid(row=1, column=1, sticky=tk.E + tk.W, padx=2, pady=2)
    btn_json = ttk.Button(outbox, text="Parcourir…", command=choose_json); btn_json.grid(row=1, column=2, padx=2, pady=2)

    ttk.Label(outbox, text="Délimiteur CSV (défaut auto):").grid(row=2, column=0, sticky=tk.E, padx=4, pady=2)
    ttk.Entry(outbox, textvariable=deli_var, width=5).grid(row=2, column=1, sticky=tk.W, padx=2, pady=2)

    toggle_csv(); toggle_json()

    # Barre + logs
    bar = ttk.Progressbar(frm, mode="indeterminate")
    bar.grid(row=6, column=0, columnspan=3, sticky=tk.E + tk.W, padx=2, pady=6)

    txt: tk.Text = tk.Text(frm, height=18)
    y_scroll = ttk.Scrollbar(frm, orient="vertical", command=txt.yview)
    txt.configure(yscrollcommand=y_scroll.set)
    txt.grid(row=7, column=0, columnspan=3, sticky=tk.N + tk.S + tk.E + tk.W, padx=2, pady=2)
    y_scroll.grid(row=7, column=3, sticky=tk.N + tk.S, padx=(0, 2), pady=2)

    status_var = tk.StringVar(value="Prêt.")
    status_bar = ttk.Label(frm, textvariable=status_var, relief="sunken", anchor="w")
    status_bar.grid(row=8, column=0, columnspan=3, sticky="we", padx=2, pady=(0, 2))

    frm.rowconfigure(7, weight=1)
    frm.columnconfigure(1, weight=1)
    frm.columnconfigure(3, weight=0)

    # Bouton Start/Stop
    btn_row = ttk.Frame(frm); btn_row.grid(row=9, column=0, columnspan=3, pady=8)
    btn_run = ttk.Button(btn_row, text="Démarrer le scan"); btn_run.pack()

    # --- File + loop de logs ---
    q: "Queue[Any]" = Queue(maxsize=5000)
    dropped = {"count": 0}
    max_per_tick = 200
    running = {"flag": False}
    cancel_event: Optional[threading.Event] = None

    def pump_log(*_args: Any) -> None:
        import re
        processed = 0
        batch: list[str] = []

        def flush() -> None:
            if batch:
                txt.insert(tk.END, "".join(batch))
                txt.see(tk.END)
                batch.clear()

        try:
            while processed < max_per_tick:
                item = q.get_nowait()
                if isinstance(item, tuple) and len(item) == 2 and item[0] == "__DONE__":
                    flush()
                    stats = cast(dict, item[1])
                    bar.stop()
                    _set_running(False)
                    txt.insert(tk.END, f"\n=== RÉSUMÉ ===\nTotal: {stats.get('total', 0)} | À risque (HIGH): {stats.get('high', 0)}\n")
                    txt.see(tk.END)
                    processed += 1
                    break

                raw = item if isinstance(item, str) else str(item)
                parts: list[str] = re.split(r"\r?\n", raw)
                split_parts: list[str] = []
                for p in parts:
                    split_parts.extend(re.split(r"\\n(?=\[[iv!+~]])", p))

                for line in split_parts:
                    line = line.rstrip()
                    if not line:
                        continue
                    if not verbose_var.get() and line.startswith("[v]"):
                        continue
                    batch.append(line + "\n")
                    processed += 1
        except Empty:
            pass

        if dropped["count"]:
            status_var.set(f" {dropped['count']} lignes omises pour fluidifier l'affichage")
            dropped["count"] = 0
        else:
            status_var.set(" Prêt.")

        flush()
        after0(app, 100, pump_log)

    def post(message: str) -> None:
        try:
            q.put_nowait(str(message))
        except Full:
            dropped["count"] += 1

    def _set_running(is_running: bool) -> None:
        running["flag"] = is_running
        state = "disabled" if is_running else "normal"
        for w in (ent_root, ent_excl, spn_depth, ent_csv, ent_json, btn_csv, btn_json):
            w.configure(state=state)
        if is_running:
            btn_run.configure(text="Arrêter le scan", state="normal")
        else:
            btn_run.configure(text="Démarrer le scan", state="normal")

    def stop_scan() -> None:
        nonlocal cancel_event
        if cancel_event and running["flag"]:
            post("[i] Demande d'arrêt reçue, arrêt en cours…")
            cancel_event.set()
            btn_run.configure(text="Arrêt en cours…", state="disabled")

    def start_scan() -> None:
        nonlocal cancel_event
        try:
            root_path = Path(root_var.get()).resolve()
        except (OSError, RuntimeError, ValueError):
            messagebox.showerror("Erreur", "Chemin racine invalide.")
            return
        exclude_names = [s.strip() for s in exclude_var.get().split(",") if s.strip()]

        ns = SimpleNamespace(
            no_npm=not scan_npm_var.get(),
            only_risk=only_risk_var.get(),
            no_scripts=not scripts_var.get(),
            sysupdater_project=sys_upd_proj_var.get(),
            sysupdater_global=sys_upd_global_var.get(),
            miners=miners_var.get(),
            persistence=persist_var.get(),
            csv=(csv_var.get().strip() if save_csv_var.get() else None),
            json=(json_var.get().strip() if save_json_var.get() else None),
            delimiter=(deli_var.get().strip() or default_csv_delimiter()),
            max_depth=max_depth_var.get(),
            follow_links=follow_links_var.get(),
            verbose=verbose_var.get(),
            hosts=hosts_var.get(),
            net_listen=net_listen_var.get(),
            shell_profiles=shell_profiles_var.get(),
            startup=startup_var.get(),
            services=services_var.get(),
            defender_exclusions=defender_var.get(),
            proxy=proxy_var.get(),
            wmi=wmi_var.get(),
            launch_globals=launch_globals_var.get(),
            login_items=login_items_var.get(),
            profiles=profiles_var.get(),
            cron_system=cron_system_var.get(),
            systemd_system=systemd_system_var.get(),
            ld_preload=ld_preload_var.get(),
            suid=suid_var.get(),
            path_world_writable=path_ww_var.get(),
            exec_timeout=EXEC_TIMEOUT,
        )

        def worker() -> None:
            try:
                _, stats = run_scan_core(root_path, exclude_names, ns, log_fn=post, cancel=cancel_event)
                q.put(("__DONE__", stats))
            except (OSError, PermissionError, FileNotFoundError, RuntimeError, ValueError,
                    subprocess.SubprocessError) as exc:
                q.put(f"[!] Erreur: {exc!r}")

        cancel_event = threading.Event()
        _set_running(True)
        txt.delete("1.0", tk.END)
        # En-tête de log côté GUI
        post(f"[i] Début du scan — {datetime.now().isoformat(timespec='seconds')}")
        post(f"[i] Racine : {root_path}")
        post(f"[i] Exclusions : {', '.join(exclude_names) if exclude_names else '(aucune)'}")
        post(f"[i] Profondeur max : {max_depth_var.get()} | Follow links: {follow_links_var.get()}")
        post(f"[i] OS : {platform.platform()} | Python {platform.python_version()}")
        bar.start(10)
        threading.Thread(target=worker, daemon=True).start()

    def on_btn_click() -> None:
        if running["flag"]:
            stop_scan()
        else:
            start_scan()

    btn_run.configure(command=on_btn_click)

    after0(app, 0, pump_log)
    try:
        app.update_idletasks()
        app.eval('tk::PlaceWindow . center')
    except tk.TclError:
        center_window(app)

    def on_close(*_args: Any) -> None:
        if running["flag"]:
            stop_scan()
            after0(app, 200, on_close)
        else:
            app.destroy()

    app.protocol("WM_DELETE_WINDOW", on_close)
    app.mainloop()
