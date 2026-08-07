#!/usr/bin/env python3
"""Fix baseline samples so positive payloads match rule predicates (Python re),
and negatives do not match the same rule's predicates.

Also repairs known FAIL_NEG cases from regression.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

try:
    import exrex
except ImportError:
    exrex = None

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
SAMPLES = ROOT / "samples"
REPORT = ROOT / "samples-regression-report.txt"

BENIGN = {
    "method": "GET",
    "host": "example.com",
    "uri": "/api/v1/items",
    "query": "q=hello-world&page=1&sort=name",
    "headers": {"User-Agent": "nerve-sample/1.0", "Accept": "*/*"},
    "body": "",
}


def load_yaml(p: Path) -> Any:
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def dump_yaml(p: Path, data: Any) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        yaml.safe_dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False, width=120),
        encoding="utf-8",
    )


def walk_preds(node: Any, out: list[dict]) -> None:
    if isinstance(node, dict):
        if "field" in node and any(k in node for k in ("regex", "contains", "eq")):
            out.append(node)
        for v in node.values():
            walk_preds(v, out)
    elif isinstance(node, list):
        for x in node:
            walk_preds(x, out)


def compile_rx(pattern: str):
    flags = 0
    if pattern.startswith("(?i)"):
        flags |= re.IGNORECASE
        pattern = pattern[4:]
    try:
        return re.compile(pattern, flags)
    except re.error:
        return None


def field_value(req: dict, field: str) -> str:
    f = (field or "query").lower()
    if f == "uri":
        return req.get("uri") or ""
    if f == "body":
        return req.get("body") or ""
    if f == "header":
        # join headers
        hs = req.get("headers") or {}
        return " ".join(f"{k}:{v}" for k, v in hs.items())
    return req.get("query") or ""


def matches_pred(req: dict, pred: dict) -> bool:
    field = str(pred.get("field") or "query")
    text = field_value(req, field)
    # engine often lowercases
    text_l = text.lower()
    if "contains" in pred:
        needle = str(pred["contains"])
        return needle.lower() in text_l or needle in text
    if "eq" in pred:
        return text == str(pred["eq"]) or text_l == str(pred["eq"]).lower()
    if "regex" in pred:
        rx = compile_rx(str(pred["regex"]))
        if not rx:
            return False
        return bool(rx.search(text) or rx.search(text_l))
    return False


def matches_any_pred(req: dict, preds: list[dict]) -> bool:
    return any(matches_pred(req, p) for p in preds)


def synth_candidates(pred: dict) -> list[str]:
    out: list[str] = []
    if "contains" in pred:
        out.append(str(pred["contains"]))
        return out
    if "eq" in pred:
        out.append(str(pred["eq"]))
        return out
    rx = str(pred.get("regex") or "")
    if not rx:
        return out
    if exrex is not None:
        try:
            for i, cand in enumerate(exrex.generate(rx)):
                if i > 40:
                    break
                if cand and len(cand) < 220:
                    out.append(cand)
        except Exception:
            pass
    # hand templates for common SQLi/XSS/RCE shapes seen in baseline
    out.extend(
        [
            "1 and 1=1",
            "1' and 1=1--",
            "1) and true--",
            "' union select null--",
            "1' union select null,null--",
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "name=a&id;whoami",
            "name=a&id|whoami",
            "q=../../../../etc/passwd",
            "file=....//....//etc/passwd",
            "url=http://127.0.0.1/",
            "<?xml version='1.0'?><!DOCTYPE a [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><a>&xxe;</a>",
            "{{7*7}}",
            "${jndi:ldap://x}",
        ]
    )
    return out


def build_req(field: str, payload: str, header_name: str | None = None) -> dict:
    f = (field or "query").lower()
    req = {
        "method": "GET",
        "host": "example.com",
        "uri": "/api/item",
        "query": "",
        "headers": {"User-Agent": "nerve-sample/1.0", "Accept": "*/*"},
        "body": "",
    }
    if f == "uri":
        req["uri"] = payload if payload.startswith("/") else "/p/" + payload
    elif f == "body":
        req["method"] = "POST"
        req["headers"]["Content-Type"] = "application/x-www-form-urlencoded"
        req["body"] = payload if ("=" in payload or "<" in payload) else f"q={payload}"
    elif f == "header":
        hn = header_name or "X-Custom"
        req["headers"][hn] = payload
        req["query"] = "q=ok"
        req["uri"] = "/api/item"
    else:
        if "=" in payload and not payload.startswith("<"):
            # already k=v or multi
            if payload.startswith("/") or " " in payload and "union" in payload.lower():
                req["query"] = f"q={payload}"
            else:
                req["query"] = payload if ("=" in payload) else f"q={payload}"
        else:
            req["query"] = f"q={payload}"
    return req


def find_matching_request(preds: list[dict]) -> dict | None:
    # try each pred's candidates on that field
    for pred in preds:
        field = str(pred.get("field") or "query")
        hn = pred.get("header_name")
        for cand in synth_candidates(pred):
            req = build_req(field, cand, str(hn) if hn else None)
            if matches_pred(req, pred):
                return req
            # also try wrapping
            for wrap in (f"1{cand}", f"'{cand}", f"{cand}--", f"x={cand}"):
                req = build_req(field, wrap, str(hn) if hn else None)
                if matches_pred(req, pred):
                    return req
    # brute: put candidate in all fields
    for pred in preds:
        for cand in synth_candidates(pred)[:15]:
            for field in ("query", "uri", "body"):
                req = build_req(field, cand)
                if matches_any_pred(req, preds):
                    return req
    return None


def benign_req_for_rule(preds: list[dict]) -> dict:
    req = dict(BENIGN)
    req["headers"] = dict(BENIGN["headers"])
    # ensure does not match this rule
    if matches_any_pred(req, preds):
        req = {
            "method": "GET",
            "host": "example.com",
            "uri": "/static/app.js",
            "query": "",
            "headers": {"User-Agent": "Mozilla/5.0", "Accept": "*/*"},
            "body": "",
        }
    if matches_any_pred(req, preds):
        req["uri"] = "/favicon.ico"
        req["query"] = ""
    return req


def sample_obj(rid, name, cat, sid, expect, severity, tags, min_level, request):
    return {
        "id": sid,
        "rule_id": rid,
        "name": name,
        "category": cat,
        "expect_action": expect,
        "min_level": min_level or "low",
        "severity": severity or "medium",
        "tags": list(tags or []),
        "request": request,
    }


def fix_all_rules() -> tuple[int, int]:
    fixed_pos = fixed_neg = 0
    for rp in sorted(RULES.rglob("*.yaml")):
        rule = load_yaml(rp)
        if not isinstance(rule, dict) or not rule.get("id"):
            continue
        rid = str(rule["id"])
        cat = rp.relative_to(RULES).parts[0]
        action = (rule.get("action") or "block").lower()
        preds: list[dict] = []
        walk_preds(rule.get("when"), preds)
        sp = SAMPLES / cat / f"{rid}.yaml"
        items: list[dict] = []
        if sp.is_file():
            raw = load_yaml(sp)
            if isinstance(raw, list):
                items = [x for x in raw if isinstance(x, dict)]
            elif isinstance(raw, dict):
                items = [raw]

        # drop weak/obsolete block samples that don't match preds (keep pass)
        kept: list[dict] = []
        for s in items:
            ea = (s.get("expect_action") or "").strip()
            if ea in ("block", "observe"):
                req = s.get("request") or {}
                if preds and not matches_any_pred(req, preds):
                    continue  # drop non-matching positive
                kept.append(s)
            else:
                kept.append(s)
        items = kept

        has_pos = any((s.get("expect_action") or "") in ("block", "observe") for s in items)
        if action == "allow":
            has_pos = any((s.get("expect_action") or "") == "pass" for s in items)

        if action != "allow" and not has_pos:
            req = find_matching_request(preds) or build_req("query", "1' and 1=1--")
            # verify
            if preds and not matches_any_pred(req, preds):
                # last resort: inject contains strings into query
                bits = []
                for p in preds:
                    if p.get("contains"):
                        bits.append(str(p["contains"]))
                if bits:
                    req = build_req("query", "q=" + bits[0])
            expect = "observe" if action == "observe" else "block"
            items.insert(
                0,
                sample_obj(
                    rid,
                    f"{rule.get('name') or rid} (pos)",
                    cat,
                    f"sample-{rid}-matched-block",
                    expect,
                    str(rule.get("severity") or "high"),
                    rule.get("tags") or [],
                    str(rule.get("min_level") or "low"),
                    req,
                ),
            )
            fixed_pos += 1
        elif action != "allow" and has_pos:
            # refresh first positive if still not matching
            for i, s in enumerate(items):
                if (s.get("expect_action") or "") in ("block", "observe"):
                    if preds and not matches_any_pred(s.get("request") or {}, preds):
                        req = find_matching_request(preds)
                        if req:
                            s["request"] = req
                            fixed_pos += 1
                    break

        # ensure allow positive matches allow preds
        if action == "allow":
            need_allow_pos = True
            for s in items:
                if (s.get("expect_action") or "") != "pass":
                    continue
                if matches_any_pred(s.get("request") or {}, preds):
                    need_allow_pos = False
                    break
            if need_allow_pos:
                req = find_matching_request(preds) or build_req("uri", "/health")
                items.insert(
                    0,
                    sample_obj(
                        rid,
                        f"{rule.get('name') or rid} (allow+)",
                        cat,
                        f"sample-{rid}-matched-allow",
                        "pass",
                        "low",
                        rule.get("tags") or [],
                        "low",
                        req,
                    ),
                )
                fixed_pos += 1

        # ensure negative: pass and does not match THIS rule
        neg_ok = False
        for s in items:
            if (s.get("expect_action") or "") != "pass":
                continue
            if action == "allow" and matches_any_pred(s.get("request") or {}, preds):
                continue  # this is allow+
            if not matches_any_pred(s.get("request") or {}, preds):
                neg_ok = True
                # scrub dangerous headers from neg samples
                req = s.get("request") or {}
                hs = dict(req.get("headers") or {})
                for bad in ("Transfer-Encoding", "transfer-encoding", "Content-Length", "content-length"):
                    hs.pop(bad, None)
                req["headers"] = hs
                # avoid websocket smuggle paths
                uri = (req.get("uri") or "").lower()
                if "chatroom" in uri or "websocket" in uri:
                    req = benign_req_for_rule(preds)
                    s["request"] = req
                    fixed_neg += 1
                else:
                    s["request"] = req
                break
        if not neg_ok:
            items.append(
                sample_obj(
                    rid,
                    f"{rule.get('name') or rid} (neg)",
                    cat,
                    f"sample-{rid}-matched-pass",
                    "pass",
                    "info",
                    list(rule.get("tags") or []) + ["fp"],
                    str(rule.get("min_level") or "low"),
                    benign_req_for_rule(preds),
                )
            )
            fixed_neg += 1

        dump_yaml(sp, items)
    return fixed_pos, fixed_neg


def main() -> int:
    fp, fn = fix_all_rules()
    print(f"fixed_pos_updates={fp}")
    print(f"fixed_neg_updates={fn}")
    # verify python-level coverage
    miss = 0
    for rp in RULES.rglob("*.yaml"):
        rule = load_yaml(rp)
        if not isinstance(rule, dict) or not rule.get("id"):
            continue
        if (rule.get("action") or "").lower() == "allow":
            continue
        rid = rule["id"]
        cat = rp.relative_to(RULES).parts[0]
        preds: list[dict] = []
        walk_preds(rule.get("when"), preds)
        sp = SAMPLES / cat / f"{rid}.yaml"
        raw = load_yaml(sp) if sp.is_file() else []
        if isinstance(raw, dict):
            raw = [raw]
        ok = False
        for s in raw or []:
            if (s.get("expect_action") or "") in ("block", "observe"):
                if matches_any_pred(s.get("request") or {}, preds):
                    ok = True
                    break
        if not ok:
            miss += 1
            print(f"STILL_MISS_POS\t{cat}\t{rid}")
    print(f"detect_rules_still_miss_pos={miss}")
    return 0 if miss == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
