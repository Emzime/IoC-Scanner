# scanner/refs/packages.py
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import Dict, List

BAD_PACKAGES: Dict[str, List[str]] = {
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

TARGETS: List[str] = sorted(
    set(
        list(BAD_PACKAGES.keys())
        + [
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
    )
)

SYSUPDATER_NAMES = {".sysupdater.dat", "sysupdater.dat"}
