#!/usr/bin/env python3
"""Ensure every baseline rule has ≥1 positive and ≥1 negative sample.

samples/<category>/<rule_id>.yaml

Detection (block/observe):
  positive → expect_action block|observe
  negative → expect_action pass

Allow:
  positive → expect_action pass (request should match allow)
  negative → expect_action pass (benign; should not need this allow)

Keeps existing samples; appends sample-<id>-gen-* when missing.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("pip install pyyaml", file=sys.stderr)
    sys.exit(1)

try:
    import exrex  # type: ignore
except ImportError:
    exrex = None

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
SAMPLES = ROOT / "samples"

CATEGORY_BLOCK: dict[str, dict[str, str]] = {
    "01-sqli": {"query": "q=1' union select null--", "uri": "/x", "body": ""},
    "13-sqli-evasions": {"query": "q=1' union select null--", "uri": "/x", "body": ""},
    "02-xss": {"query": "q=<script>alert(1)</script>", "uri": "/x", "body": ""},
    "12-xss-evasions": {"query": "q=<svg/onload=alert(1)>", "uri": "/x", "body": ""},
    "03-rce-cmdi": {"query": "name=a&id;whoami", "uri": "/x", "body": ""},
    "05-rce": {"query": "cmd=$(whoami)", "uri": "/x", "body": ""},
    "04-lfi-path": {"query": "file=../../etc/passwd", "uri": "/x", "body": ""},
    "05-rfi-ssrf": {"query": "url=http://127.0.0.1:22", "uri": "/x", "body": ""},
    "06-xxe-ssti": {
        "query": "",
        "uri": "/x",
        "body": "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
    },
    "07-webshell": {"query": "", "uri": "/shell.php", "body": "<?=`id`;?>"},
    "08-admin-scanner": {"query": "", "uri": "/admin/config", "body": ""},
    "09-known-bad": {"query": "q=../../../etc/passwd", "uri": "/x", "body": ""},
    "09-info": {"query": "", "uri": "/server-status", "body": ""},
    "10-php-java": {"query": "", "uri": "/x.jsp", "body": '<% Runtime.getRuntime().exec("id"); %>'},
    "11-observe": {"query": "q=suspicious-but-observe", "uri": "/x", "body": ""},
    "14-upload-rce-java": {
        "query": "",
        "uri": "/upload",
        "body": '------B\r\nContent-Disposition: form-data; name="f"; filename="x.jsp"\r\n\r\n<% %>\r\n------B--',
    },
    "00-allow": {"query": "", "uri": "/health", "body": ""},
    "90-allow": {"query": "", "uri": "/health", "body": ""},
}

BENIGN_QUERY = "q=hello-world&page=1&id=550e8400-e29b-41d4-a716-446655440000"


def load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def dump_samples(path: Path, items: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    items = sorted(
        items,
        key=lambda s: (
            0 if (s.get("expect_action") or "") in ("block", "observe") else 1,
            s.get("id") or "",
        ),
    )
    path.write_text(
        yaml.safe_dump(
            items,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
            width=120,
        ),
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


def simplify_regex(rx: str) -> str | None:
    s = re.sub(r"^\(\?i\)", "", rx)
    s = re.sub(r"\(\?:", "(", s)
    for _ in range(10):
        s2 = re.sub(r"\(([^()|*+?\\]+)\|[^)]+\)", r"\1", s)
        if s2 == s:
            break
        s = s2
    s = s.replace(r"\s+", " ").replace(r"\s*", "").replace(r"\s", " ")
    s = s.replace(r"\d+", "1").replace(r"\d", "1")
    s = s.replace(r"\w+", "a").replace(r"\w", "a")
    s = s.replace(r"\b", "")
    s = s.replace(r"\.", ".").replace(r"\/", "/")
    s = s.replace(r"\'", "'").replace(r"\"", '"')
    s = s.replace(r"\(", "(").replace(r"\)", ")")
    s = re.sub(r"\[\^[^\]]*\][\*\+]?", "x", s)
    s = re.sub(r"\[[^\]]*\]", "a", s)
    s = re.sub(r"\{[^}]+\}", "", s)
    s = s.replace("?", "").replace("+", "").replace("*", "")
    s = s.replace("^", "").replace("$", "")
    s = re.sub(r"[()]", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    if not s or len(s) > 180:
        return None
    if re.search(r"[\\[\]|*+?{}]", s):
        return None
    return s


def synth_from_regex(rx: str) -> str | None:
    if exrex is not None:
        try:
            for i, cand in enumerate(exrex.generate(rx)):
                if i > 30:
                    break
                if cand and 0 < len(cand) < 200:
                    return cand
        except Exception:
            pass
    return simplify_regex(rx)


def header_name_of(rule: dict) -> str | None:
    preds: list[dict] = []
    walk_preds(rule.get("when"), preds)
    for p in preds:
        if p.get("header_name"):
            return str(p["header_name"])
    return None


def build_request(field: str, payload: str, header_name: str | None = None) -> dict:
    method = "GET"
    uri = "/api/search"
    query = BENIGN_QUERY
    body = ""
    headers: dict[str, str] = {"User-Agent": "nerve-sample/1.0", "Accept": "*/*"}
    f = (field or "query").lower()
    if f == "uri":
        uri = payload if payload.startswith("/") else "/" + payload.lstrip("/")
        query = ""
    elif f == "body":
        method = "POST"
        body = payload if ("=" in payload or payload.startswith("<") or payload.startswith("-")) else f"payload={payload}"
        query = ""
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif f == "header":
        headers[header_name or "X-Forwarded-For"] = payload
        query = "q=ok"
    else:
        if payload.startswith("q=") or "&" in payload or "=" in payload:
            query = payload
        else:
            query = f"q={payload}"
    return {
        "method": method,
        "host": "example.com",
        "uri": uri,
        "query": query,
        "headers": headers,
        "body": body,
    }


def category_block_req(cat: str) -> dict:
    base = CATEGORY_BLOCK.get(cat) or {"query": "q=attack-probe", "uri": "/x", "body": ""}
    headers = {"User-Agent": "nerve-sample/1.0", "Accept": "*/*"}
    method = "GET"
    body = base.get("body") or ""
    if body:
        method = "POST"
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    return {
        "method": method,
        "host": "example.com",
        "uri": base.get("uri") or "/x",
        "query": base.get("query") or "",
        "headers": headers,
        "body": body,
    }


def benign_req() -> dict:
    return {
        "method": "GET",
        "host": "example.com",
        "uri": "/api/search",
        "query": BENIGN_QUERY,
        "headers": {"User-Agent": "nerve-sample/1.0", "Accept": "*/*"},
        "body": "",
    }


def pick_attack_request(rule: dict, cat: str) -> dict:
    preds: list[dict] = []
    walk_preds(rule.get("when"), preds)
    hn = header_name_of(rule)
    for p in preds:
        if p.get("contains"):
            return build_request(str(p.get("field") or "query"), str(p["contains"]), hn)
    for p in preds:
        if p.get("eq") is not None:
            return build_request(str(p.get("field") or "query"), str(p["eq"]), hn)
        if p.get("regex"):
            got = synth_from_regex(str(p["regex"]))
            if got:
                return build_request(str(p.get("field") or "query"), got, hn)
    return category_block_req(cat)


def make_sample(
    *,
    rid: str,
    name: str,
    cat: str,
    sid: str,
    expect: str,
    severity: str,
    tags: list,
    min_level: str,
    request: dict,
) -> dict:
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


def main() -> int:
    if exrex is None:
        print("note: exrex not installed; using simplify + category fallback")

    rules: list[tuple[Path, dict]] = []
    for p in sorted(RULES.rglob("*.yaml")):
        d = load_yaml(p)
        if isinstance(d, dict) and d.get("id"):
            rules.append((p, d))

    added_pos = added_neg = touched = 0

    for path, rule in rules:
        rid = str(rule["id"])
        rel = path.relative_to(RULES)
        cat = rel.parts[0] if len(rel.parts) > 1 else "misc"
        action = (rule.get("action") or "block").strip().lower()
        is_allow = action == "allow"
        sample_path = SAMPLES / cat / f"{rid}.yaml"

        items: list[dict] = []
        if sample_path.is_file():
            raw = load_yaml(sample_path)
            if isinstance(raw, list):
                items = [x for x in raw if isinstance(x, dict)]
            elif isinstance(raw, dict):
                items = [raw]

        ids = {(s.get("id") or "") for s in items}
        expects = [(s.get("expect_action") or "").strip() for s in items]

        if is_allow:
            need_pos = not any(e == "pass" for e in expects)
            need_neg = f"sample-{rid}-gen-pass" not in ids
        else:
            need_pos = not any(e in ("block", "observe") for e in expects)
            need_neg = not any(e == "pass" for e in expects)

        if not need_pos and not need_neg:
            continue

        tags = rule.get("tags") or []
        severity = str(rule.get("severity") or ("low" if is_allow else "high"))
        min_level = str(rule.get("min_level") or "low")
        rname = str(rule.get("name") or rid)

        if need_pos:
            if is_allow:
                items.append(
                    make_sample(
                        rid=rid,
                        name=f"{rname} (allow+)",
                        cat=cat,
                        sid=f"sample-{rid}-gen-allow-pos",
                        expect="pass",
                        severity=severity,
                        tags=tags,
                        min_level=min_level,
                        request=pick_attack_request(rule, cat),
                    )
                )
            else:
                expect = "observe" if action == "observe" else "block"
                items.append(
                    make_sample(
                        rid=rid,
                        name=f"{rname} (pos)",
                        cat=cat,
                        sid=f"sample-{rid}-gen-block",
                        expect=expect,
                        severity=severity,
                        tags=tags,
                        min_level=min_level,
                        request=pick_attack_request(rule, cat),
                    )
                )
            added_pos += 1

        if need_neg:
            items.append(
                make_sample(
                    rid=rid,
                    name=f"{rname} (neg)",
                    cat=cat,
                    sid=f"sample-{rid}-gen-pass",
                    expect="pass",
                    severity="info",
                    tags=list(tags) + ["fp"],
                    min_level=min_level,
                    request=benign_req(),
                )
            )
            added_neg += 1

        dump_samples(sample_path, items)
        touched += 1

    print(f"rules={len(rules)}")
    print(f"files_updated={touched}")
    print(f"pos_added={added_pos}")
    print(f"neg_added={added_neg}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
