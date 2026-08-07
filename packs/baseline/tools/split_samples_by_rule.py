#!/usr/bin/env python3
"""Split packs/baseline/samples/*.yaml into samples/<category>/<rule_id>.yaml.

Mirrors rules/<category>/<rule_id>.yaml. Does not invent samples for rules
that have none. Run from repo root or any cwd:

  python3 packs/baseline/tools/split_samples_by_rule.py
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:
    print("need PyYAML: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


ROOT = Path(__file__).resolve().parents[1]  # packs/baseline
SAMPLES = ROOT / "samples"
RULES = ROOT / "rules"


def load_rule_categories() -> dict[str, str]:
    """rule_id -> category dir name."""
    out: dict[str, str] = {}
    for p in RULES.rglob("*.yaml"):
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        rid = data.get("id")
        if not rid:
            continue
        # category = parent folder under rules/
        try:
            rel = p.relative_to(RULES)
            cat = rel.parts[0] if len(rel.parts) > 1 else "misc"
        except ValueError:
            cat = "misc"
        out[str(rid)] = cat
    return out


def dump_samples(path: Path, items: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Stable order: block first, then by sample id
    items = sorted(
        items,
        key=lambda s: (
            0 if (s.get("expect_action") or "") == "block" else 1,
            s.get("id") or "",
        ),
    )
    text = yaml.safe_dump(
        items,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
        width=120,
    )
    path.write_text(text, encoding="utf-8")


def main() -> int:
    rule_cat = load_rule_categories()
    flat_files = sorted(SAMPLES.glob("*.yaml"))
    if not flat_files:
        print(f"no flat samples in {SAMPLES}")
        return 1

    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    skipped = 0

    for f in flat_files:
        data = yaml.safe_load(f.read_text(encoding="utf-8"))
        if data is None:
            continue
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            print(f"skip non-list {f.name}")
            skipped += 1
            continue
        for s in data:
            if not isinstance(s, dict):
                skipped += 1
                continue
            rid = str(s.get("rule_id") or "").strip()
            if not rid:
                # keep orphans under _ungrouped
                cat = str(s.get("category") or f.stem)
                grouped[(cat, "_no_rule_id")].append(s)
                continue
            cat = str(s.get("category") or "").strip() or rule_cat.get(rid) or f.stem
            # normalize category to rule folder when known
            if rid in rule_cat:
                cat = rule_cat[rid]
            s["category"] = cat
            s["rule_id"] = rid
            grouped[(cat, rid)].append(s)

    written = 0
    for (cat, rid), items in sorted(grouped.items()):
        out = SAMPLES / cat / f"{rid}.yaml"
        dump_samples(out, items)
        written += 1

    # remove old flat category files (keep README.md)
    removed = 0
    for f in flat_files:
        f.unlink()
        removed += 1

    print(f"rules_indexed={len(rule_cat)}")
    print(f"sample_files_written={written}")
    print(f"flat_files_removed={removed}")
    print(f"skipped_entries={skipped}")
    rules_with = {rid for (_, rid) in grouped if rid != "_no_rule_id"}
    print(f"rules_with_samples={len(rules_with)}")
    print(f"rules_without_samples={len(set(rule_cat) - rules_with)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
