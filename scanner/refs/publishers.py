# scanner/refs/publishers.py
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import List

TRUSTED_PUBLISHERS: List[str] = [
    # OS et éditeurs majeurs
    "Microsoft Corporation",
    "Apple Inc.",
    "Google LLC",
    "Mozilla Corporation",
    "Canonical Ltd.",
    "Red Hat, Inc.",
    "The Document Foundation",   # LibreOffice

    # Développement / Java / IDE
    "Oracle America, Inc.",
    "Eclipse Foundation",
    "JetBrains s.r.o.",

    # Graphisme / multimédia
    "Adobe Inc.",
    "Corel Corporation",
    "Autodesk, Inc.",

    # Matériel / pilotes
    "Intel Corporation",
    "NVIDIA Corporation",
    "Advanced Micro Devices, Inc.",
    "Qualcomm Technologies, Inc.",
    "Broadcom Inc.",
    "Realtek Semiconductor Corp.",

    # Virtualisation / sécurité
    "VMware, Inc.",
    "Cisco Systems, Inc.",
    "Fortinet, Inc.",
    "Check Point Software Technologies Ltd.",
    "Sophos Ltd.",
    "Kaspersky Lab",
    "Bitdefender SRL",
    "ESET, spol. s r.o.",

    # Autres éditeurs connus
    "Zoom Video Communications, Inc.",
    "Dropbox, Inc.",
    "Spotify AB",
    "Valve Corporation",
    "Electronic Arts, Inc.",
    "Ubisoft Entertainment",
    "Activision Blizzard, Inc.",
]
