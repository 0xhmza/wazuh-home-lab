"""Loads real-world log lines from bundled or fetched datasets.

The generator can replay these lines (rewritten with the local hostname and a
fresh timestamp) so a Wazuh dashboard sees alerts whose pattern, payload, and
distribution match real production traffic, not just synthetic templates.

Layout on disk:

    datasets/
      <dataset-name>/
         *.log         <- one log line per line, raw ascii / utf-8
         meta.json     <- optional; { "category": "auth" | "web" | ... }

Categories drive the Wazuh dashboard's grouping and the UI's colour scheme.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from random import Random


# Recognised in line prefixes; we strip these so the replayed line carries the
# replaying agent's hostname/timestamp instead of the original sample's.
_SYSLOG_PREFIX_RE = re.compile(
    r"""^
        (?:
          (?:[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})           # syslog short ts
          | (?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)  # iso ts
        )
        \s+
        (?:[\w.\-]+\s+)?                                         # optional hostname
    """,
    re.VERBOSE,
)


@dataclass
class Dataset:
    name: str
    category: str
    lines: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not self.lines

    def pick(self, rng: Random) -> str:
        return rng.choice(self.lines)


def _read_lines(path: Path, max_per_file: int = 5000) -> list[str]:
    out: list[str] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.rstrip("\r\n")
                if not line or line.startswith("#"):
                    continue
                out.append(line)
                if len(out) >= max_per_file:
                    break
    except OSError:
        return []
    return out


def _strip_prefix(line: str) -> str:
    return _SYSLOG_PREFIX_RE.sub("", line, count=1).lstrip()


def load_datasets(root: Path) -> dict[str, Dataset]:
    """Read every dataset under `root` into memory.

    Each subdirectory becomes one Dataset. Lines from every file in that
    subdirectory are merged. Lines have leading timestamp+hostname stripped so
    the replay scenario can prepend the replaying endpoint's own values.
    """
    if not root.is_dir():
        return {}

    out: dict[str, Dataset] = {}
    for sub in sorted(p for p in root.iterdir() if p.is_dir()):
        category = "noise"
        meta_path = sub / "meta.json"
        if meta_path.is_file():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                category = str(meta.get("category", category))
            except (OSError, json.JSONDecodeError):
                pass

        lines: list[str] = []
        for log_file in sorted(sub.glob("*.log")):
            for line in _read_lines(log_file):
                stripped = _strip_prefix(line)
                if stripped:
                    lines.append(stripped)
        for log_file in sorted(sub.glob("*.txt")):
            for line in _read_lines(log_file):
                stripped = _strip_prefix(line)
                if stripped:
                    lines.append(stripped)

        if lines:
            out[sub.name] = Dataset(name=sub.name, category=category, lines=lines)

    return out


def merge_lines(datasets: dict[str, Dataset]) -> list[str]:
    """Return a flat de-duplicated list of every line across all datasets."""
    seen: set[str] = set()
    out: list[str] = []
    for ds in datasets.values():
        for line in ds.lines:
            if line not in seen:
                seen.add(line)
                out.append(line)
    return out
