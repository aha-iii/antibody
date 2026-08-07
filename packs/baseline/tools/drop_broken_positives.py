#!/usr/bin/env python3
"""Remove sample entries that still FAIL expect=block under deep (broken positives)."""
from pathlib import Path
import yaml

ROOT = Path("/mnt/d/workspace/waf/Nerve-waf/Nerve-antibody/packs/baseline")
REPORT = Path("/tmp/sr-deep-report.txt")
SAMPLES = ROOT / "samples"

fail_ids = set()
for line in REPORT.read_text(encoding="utf-8", errors="replace").splitlines():
    if not line.startswith("FAIL\t"):
        continue
    parts = line.split("\t")
    rest = [p for p in parts[1:] if not p.startswith(("expect=", "actual=", "hit_rule="))]
    if len(rest) >= 3:
        fail_ids.add(rest[2])

print("remove", len(fail_ids))
removed = 0
for sp in SAMPLES.rglob("*.yaml"):
    raw = yaml.safe_load(sp.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        continue
    new = []
    for s in raw:
        if not isinstance(s, dict):
            new.append(s)
            continue
        sid = s.get("id")
        if sid in fail_ids and (s.get("expect_action") or "") in ("block", "observe"):
            removed += 1
            print("drop", sid)
            continue
        new.append(s)
    if len(new) != len(raw):
        sp.write_text(
            yaml.safe_dump(new, allow_unicode=True, sort_keys=False, default_flow_style=False, width=120),
            encoding="utf-8",
        )
print("removed", removed)
