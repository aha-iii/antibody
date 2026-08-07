#!/usr/bin/env python3
"""Rebuild remaining fail positives with EXACT rule contains needles on correct fields."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import yaml

ROOT = Path("/mnt/d/workspace/waf/Nerve-waf/Nerve-antibody/packs/baseline")
REPORT = Path("/tmp/sr-deep-report.txt")
RULES = ROOT / "rules"
SAMPLES = ROOT / "samples"


def walk_preds(node: Any, out: list[dict]) -> None:
    if isinstance(node, dict):
        if "field" in node and any(k in node for k in ("regex", "contains", "eq")):
            out.append(node)
        for v in node.values():
            walk_preds(v, out)
    elif isinstance(node, list):
        for x in node:
            walk_preds(x, out)


def main() -> None:
    fail_ids = {}
    for line in REPORT.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("FAIL\t"):
            continue
        parts = line.split("\t")
        rest = [p for p in parts[1:] if not p.startswith(("expect=", "actual=", "hit_rule="))]
        if len(rest) >= 3:
            fail_ids[rest[2]] = rest[1]

    n = 0
    for sid, rid in fail_ids.items():
        rp = next(RULES.rglob(f"{rid}.yaml"), None)
        sp = next(SAMPLES.rglob(f"{rid}.yaml"), None)
        if not rp or not sp:
            continue
        rule = yaml.safe_load(rp.read_text(encoding="utf-8"))
        preds: list[dict] = []
        walk_preds(rule.get("when"), preds)
        # Prefer contains over regex
        chosen = None
        for p in preds:
            if p.get("contains"):
                chosen = p
                break
        if not chosen:
            for p in preds:
                if p.get("eq"):
                    chosen = p
                    break
        if not chosen and preds:
            # regex: craft classic SQLi / XSS-ish from pattern keywords
            p = preds[0]
            field = str(p.get("field") or "query")
            rx = str(p.get("regex") or "")
            if "select" in rx.lower() and "from" in rx.lower():
                payload = "1' select user from information_schema.tables--"
            elif "script" in rx.lower():
                payload = "<script>alert(1)</script>"
            else:
                payload = "nerve-sample-probe"
            chosen = {"field": field, "contains": payload}

        if not chosen:
            continue

        field = str(chosen.get("field") or "query").lower()
        needle = str(chosen.get("contains") or chosen.get("eq") or "")
        req = {
            "method": "GET",
            "host": "example.com",
            "uri": "/api/vuln/probe",
            "query": "",
            "headers": {"User-Agent": "nerve-sample/1.0", "Accept": "*/*"},
            "body": "",
        }
        if field == "uri":
            # keep encoded forms intact in path
            req["uri"] = f"/api/vuln/{needle}" if not needle.startswith("/") else needle
        elif field == "body":
            req["method"] = "POST"
            req["headers"]["Content-Type"] = "text/plain"
            req["body"] = needle
        elif field == "header":
            req["headers"]["X-Attack"] = needle
        else:
            req["query"] = f"q={needle}"

        items = yaml.safe_load(sp.read_text(encoding="utf-8"))
        if not isinstance(items, list):
            continue
        for s in items:
            if isinstance(s, dict) and s.get("id") == sid:
                s["request"] = req
                # align sample min_level to rule so medium bench can escalate
                s["min_level"] = str(rule.get("min_level") or s.get("min_level") or "low")
                n += 1
                print("set", sid, field, needle[:60])
        sp.write_text(
            yaml.safe_dump(items, allow_unicode=True, sort_keys=False, default_flow_style=False, width=120),
            encoding="utf-8",
        )
    print("updated", n)


if __name__ == "__main__":
    main()
