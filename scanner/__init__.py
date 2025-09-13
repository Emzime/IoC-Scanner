# scanner/__init__.py
# -*- coding: utf-8 -*-

from .refs.labels import SEVERITY_LABEL
from .core import run_scan_core

__all__ = [
    "SEVERITY_LABEL",
    "run_scan_core",
]

