from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from httpx2_kerberos.__version__ import __version__


project = "httpx2_kerberos"
author = "Andrew C"
copyright = "2026, Andrew C"
release = __version__
version = __version__

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.doctest",
    "sphinx.ext.napoleon",
]

autodoc_member_order = "bysource"
autodoc_typehints = "description"
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
html_theme = "alabaster"