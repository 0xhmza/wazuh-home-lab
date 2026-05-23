"""Fetch a HuggingFace dataset and write it as plain log lines.

Usage::

    python app/fetch_dataset.py \
        --dataset cybernative/Code_Vulnerability_Security_DPO \
        --column rejected \
        --output datasets/hf-cve-attempts \
        --max-lines 5000 \
        --category web

Requires the optional dependency::

    python -m pip install datasets

The output directory will contain `data.log` (one line per row) and
`meta.json` (so the lab generator picks the right colour/category).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dataset", required=True, help="HuggingFace dataset name, e.g. 'org/name'.")
    parser.add_argument("--config", default=None, help="Optional dataset configuration name.")
    parser.add_argument("--split", default="train", help="Dataset split to read (default: train).")
    parser.add_argument("--column", required=True, help="Name of the column containing the log/text payload.")
    parser.add_argument("--output", required=True, type=Path, help="Output directory under datasets/.")
    parser.add_argument("--max-lines", type=int, default=5000, help="Max rows to write (default: 5000).")
    parser.add_argument("--category", default="noise", choices=["auth", "privesc", "web", "network", "lateral", "persist", "exfil", "impact", "discovery", "noise"], help="Lab category for colouring (default: noise).")
    parser.add_argument("--max-line-chars", type=int, default=2000, help="Truncate any single line longer than this (default: 2000).")
    args = parser.parse_args()

    try:
        from datasets import load_dataset  # type: ignore
    except ImportError:
        print("error: the 'datasets' package is required.", file=sys.stderr)
        print("       run: python -m pip install datasets", file=sys.stderr)
        return 2

    print(f"loading {args.dataset} (split={args.split}, config={args.config})...")
    if args.config:
        ds = load_dataset(args.dataset, args.config, split=args.split)
    else:
        ds = load_dataset(args.dataset, split=args.split)

    if args.column not in ds.column_names:
        print(f"error: column '{args.column}' not in dataset. Available: {ds.column_names}", file=sys.stderr)
        return 2

    args.output.mkdir(parents=True, exist_ok=True)
    out_path = args.output / "data.log"
    written = 0
    with out_path.open("w", encoding="utf-8") as fh:
        for row in ds:
            value = row.get(args.column)
            if value is None:
                continue
            text = str(value).replace("\r", " ").replace("\n", " ").strip()
            if not text:
                continue
            if len(text) > args.max_line_chars:
                text = text[: args.max_line_chars]
            fh.write(text + "\n")
            written += 1
            if written >= args.max_lines:
                break

    meta = {
        "category": args.category,
        "source": f"huggingface:{args.dataset}",
        "column": args.column,
        "split": args.split,
        "lines": written,
    }
    (args.output / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {written} lines to {out_path}")
    print(f"wrote metadata to {args.output / 'meta.json'}")
    print("Restart the lab (scripts/up.ps1) for the generator to pick up the new dataset.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
