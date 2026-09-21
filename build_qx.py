#!/usr/bin/env python3
"""Convert VME98/jinx-rules (Jinx DNS filter rules) into a single Quantumult X filter file.

Usage: python3 build_qx.py <upstream_rules_dir> <output_file>

Whitelist rules become DIRECT (placed first to avoid false positives),
blacklist domain/url rules become REJECT.
"""
import re
import sys
from pathlib import Path


def read(rules_dir: Path, name: str):
    return [
        line.strip()
        for line in (rules_dir / name).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def is_url_rule(s: str) -> bool:
    return s.startswith("http://") or s.startswith("https://")


def domain_to_qx(d: str):
    """jinx domain/wildcard -> QX host rule. Returns None if not expressible."""
    d = d.lower()
    if not re.match(r"^[a-z0-9*._-]+$", d):
        return None
    if d.startswith("*."):
        base = d[2:]
        if "*" in base:
            return None
        return ("domain-keyword", base) if "." not in base else ("domain-suffix", base)
    if "*" in d:
        return None
    return ("domain-suffix", d)


def main():
    rules_dir = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    lines_direct, lines_reject = [], []
    seen_direct, seen_reject = set(), set()

    def add(bucket, seen, tag, value):
        key = (tag, value)
        if key not in seen:
            seen.add(key)
            bucket.append(f"{tag},{value}")

    # --- whitelist: domains -> DIRECT ---
    for d in read(rules_dir, "domain_whitelist.txt"):
        r = domain_to_qx(d)
        if r:
            add(lines_direct, seen_direct, r[0], r[1])
    for d in read(rules_dir, "whitelist_wildcard.txt"):
        r = domain_to_qx(d)
        if r:
            add(lines_direct, seen_direct, r[0], r[1])
    for d in read(rules_dir, "whitelist.txt"):
        if not is_url_rule(d):
            r = domain_to_qx(d)
            if r:
                add(lines_direct, seen_direct, r[0], r[1])

    # --- URL whitelist (full URLs, whitelist beats blacklist) -> DIRECT ---
    full_urls_w = read(rules_dir, "url_whitelist.txt")

    # --- blacklist: domains -> REJECT ---
    for d in read(rules_dir, "domain_blacklist.txt"):
        r = domain_to_qx(d)
        if r:
            add(lines_reject, seen_reject, r[0], r[1])
    for d in read(rules_dir, "blacklist_wildcard.txt"):
        if not is_url_rule(d):
            r = domain_to_qx(d)
            if r:
                add(lines_reject, seen_reject, r[0], r[1])
    for d in read(rules_dir, "blacklist.txt"):
        if not is_url_rule(d):
            r = domain_to_qx(d)
            if r:
                add(lines_reject, seen_reject, r[0], r[1])

    # --- URL blacklist (full URLs) -> REJECT url-reg ---
    url_reject = []
    for u in read(rules_dir, "url_blacklist_domain_paths.txt") + [
        x for x in read(rules_dir, "url_blacklist.txt") if is_url_rule(x)
    ]:
        m = re.match(r"^(https?)://([^/]+)(/.*)$", u)
        if not m:
            continue
        host, path = m.group(2), m.group(3)
        path_rx = re.escape(path).replace(r"\*", ".*").replace(r"\-", "-")
        host_rx = re.escape(host).replace(r"\*", "[^.]*").replace(r"\-", "-")
        url_reject.append(f"^https?://{host_rx}{path_rx}")

    for rx in url_reject:
        add(lines_reject, seen_reject, "url-reg", rx)

    # --- path blacklist (path-only rules apply to any host) -> REJECT url-reg ---
    for p in read(rules_dir, "url_blacklist_paths.txt"):
        rx = re.escape(p).replace(r"\*", ".*").replace(r"\-", "-")
        add(lines_reject, seen_reject, "url-reg", rx)

    # --- URL whitelist full urls -> DIRECT url-reg (must precede rejects) ---
    url_wl = []
    for u in full_urls_w:
        m = re.match(r"^(https?)://([^/]+)(/.*)$", u)
        if m:
            host_rx = re.escape(m.group(2)).replace(r"\.", r"\.")
            path_rx = re.escape(m.group(3)).replace(r"\*", ".*").replace(r"\-", "-")
            url_wl.append(f"url-reg,^https?://{host_rx}{path_rx}")
        else:
            rx = re.escape(u).replace(r"\*", ".*").replace(r"\-", "-")
            url_wl.append(f"url-reg,{rx}")

    header = (
        "# Quantumult X 去广告/白名单合并分流规则\n"
        "# 由 VME98/jinx-rules 自动合并生成，请勿手工编辑\n"
        "# 白名单（DIRECT）在前，黑名单（REJECT）在后\n"
        "# 更新时间见仓库提交记录\n"
        "\n"
    )

    content = header
    content += "# ==== 白名单：这些请求直连放行，防止误杀 ====\n"
    content += "\n".join(lines_direct) + "\n"
    content += "\n# ==== URL 白名单 ====\n"
    content += "\n".join(url_wl) + "\n"
    content += "\n# ==== 广告域名/URL 拦截 ====\n"
    content += "\n".join(lines_reject) + "\n"
    out_path.write_text(content, encoding="utf-8")

    print(
        f"written {out_path}: {len(lines_direct) + len(url_wl)} whitelist rules, "
        f"{len(lines_reject)} reject rules"
    )


if __name__ == "__main__":
    main()
