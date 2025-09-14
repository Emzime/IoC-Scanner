# scanner/refs/packages.py
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import Dict, List

from scanner.utils import fetch_json, SIGNATURE_BASE_URL, CACHE_DIR

# ---------------------------------------------------------------------------
# Valeurs par défaut (fallback si GitHub est inaccessible)
# ---------------------------------------------------------------------------

DEFAULT_BAD_PACKAGES: Dict[str, List[str]] = {
    "debug": ["4.4.2"],
    "color-name": ["2.0.1"],
    "strip-ansi": ["7.1.1"],
    "color": ["5.0.1"],
    "color-convert": ["3.1.1"],
    "color-string": ["2.1.1"],
    "has-ansi": ["6.0.1"],
    "ansi-styles": ["6.2.2"],
    "ansi-regex": ["6.2.1"],
    "supports-color": ["10.2.1"],
    "chalk": ["5.6.1"],
    "backslash": ["0.2.1"],
    "wrap-ansi": ["9.0.1"],
    "is-arrayish": ["0.3.3"],
    "error-ex": ["1.3.3"],
    "slice-ansi": ["7.1.1"],
    "simple-swizzle": ["0.2.3"],
    "chalk-template": ["1.1.1"],
    "supports-hyperlinks": ["4.1.1"],
    "duckdb": ["1.3.3"],
    "@duckdb/node-api": ["1.3.3"],
    "@duckdb/node-bindings": ["1.3.3"],
    "@duckdb/duckdb-wasm": ["1.29.2"],
}

DEFAULT_EXTRA_TARGETS: List[str] = [
    "supports-color",
    "ansi-styles",
    "ansi-regex",
    "wrap-ansi",
    "slice-ansi",
    "chalk-template",
    "supports-hyperlinks",
    "color-name",
    "color-string",
    "color-convert",
    "is-arrayish",
    "error-ex",
    "simple-swizzle",
    "backslash",
    "chalk",
    "debug",
    "duckdb",
    "@duckdb/node-api",
    "@duckdb/node-bindings",
    "@duckdb/duckdb-wasm",
]

# ---------------------------------------------------------------------------
# Chargement dynamique depuis le dépôt 'ioc-signatures'
# ---------------------------------------------------------------------------

_bad_packages = fetch_json(
    f"{SIGNATURE_BASE_URL}/bad_packages.json",
    CACHE_DIR / "bad_packages.json"
)
if not _bad_packages:
    _bad_packages = DEFAULT_BAD_PACKAGES

extra_targets = fetch_json(
    f"{SIGNATURE_BASE_URL}/targets.json",
    CACHE_DIR / "targets.json"
).get("extra_targets", [])
if not extra_targets:
    extra_targets = DEFAULT_EXTRA_TARGETS

# Paquets compromis connus
BAD_PACKAGES: Dict[str, List[str]] = _bad_packages

# Paquets à surveiller (compromis + extra)
TARGETS: List[str] = sorted(set(BAD_PACKAGES.keys()) | set(extra_targets))

# IoC fixes
SYSUPDATER_NAMES = {".sysupdater.dat", "sysupdater.dat"}

__all__ = ["BAD_PACKAGES", "TARGETS", "SYSUPDATER_NAMES"]
