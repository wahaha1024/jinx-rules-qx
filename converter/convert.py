#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jinx-rules-qx :: convert VME98/jinx-rules into Quantumult X rule files.

Generates under generated/:
  jinx-qx-filter.list   host rules (whitelist->direct first, then blacklist->reject)
  jinx-qx-rewrite.conf  URL regex rewrite rules ([rewrite_local] snippet)
  jinx-mitm-skip.txt    domains the user should keep OUT of their [mitm] hostname
  unsupported.log       rules that were NOT converted, with reasons

Usage:
  python converter/convert.py                    # download from upstream
  python converter/convert.py --source-dir DIR   # read from a local checkout of the upstream repo
"""

import argparse
import fnmatch
import json
import os
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT, "config", "sources.json")
OUT_DIR = os.path.join(ROOT, "generated")

RAW_URL = "https://raw.githubusercontent.com/{repo}/{branch}/{path}"
API_COMMIT = "https://api.github.com/repos/{repo}/commits/{branch}"

URL_SCHEME_RE = re.compile(r"^https?://", re.I)
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")
URL_PARTS_RE = re.compile(r"^(https?)://([^/?#]+)([^?#]*)(\?[^#]*)?(#.*)?$")
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$")
WILDCARD_CHARS_RE = re.compile(r"^[a-z0-9.*?_-]+$")
# characters that make a path a real regex rather than a literal/wildcard path
REGEX_METACHARS = set("()[]{}+^$|\\")

KIND_ORDER = {"exact": 0, "suffix": 1, "wildcard": 2, "keyword": 3, "ip": 4}
KIND_TYPE = {"exact": "host", "suffix": "host-suffix", "wildcard": "host-wildcard",
             "keyword": "host-keyword", "ip": "ip-cidr"}

# --- extra source: Surge/Shadowrocket .sgmodule merge support ---
SG_KIND = {"DOMAIN": "exact", "DOMAIN-SUFFIX": "suffix", "DOMAIN-WILDCARD": "wildcard",
           "DOMAIN-KEYWORD": "keyword", "IP-CIDR": "ip", "IP6-CIDR": "ip"}
SG_REWRITE_ACTIONS = {"reject", "reject-200", "reject-img", "reject-dict", "reject-array"}
SGM_RW_RE = re.compile(r"^(\S+)\s+-\s+([A-Za-z0-9-]+)$")
KEYWORD_RE = re.compile(r"^[a-z0-9._-]+$")


def new_bucket():
    return {"exact": set(), "suffix": set(), "wildcard": set(), "keyword": set(), "ip": set()}


def log(msg):
    print(msg, flush=True)


# ---------------------------------------------------------------- loading

def fetch(url, tries=3, timeout=25):
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "jinx-rules-qx/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001 - network errors are expected, retry then raise
            last = e
            time.sleep(2 * (i + 1))
    raise RuntimeError("download failed: %s (%s)" % (url, last))


def upstream_commit(repo, branch):
    try:
        req = urllib.request.Request(
            API_COMMIT.format(repo=repo, branch=branch),
            headers={"User-Agent": "jinx-rules-qx/1.0", "Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            return str(json.load(r).get("sha", "unknown"))[:12]
    except Exception:  # noqa: BLE001 - best effort, header falls back to "unknown"
        return "unknown"


def load_sources(cfg, source_dir):
    src = cfg["sources"]
    paths = list(src["domain"]["blacklist"]) + list(src["domain"]["whitelist"])
    paths += list(src["url"]["blacklist"]) + list(src["url"]["whitelist"])
    paths += list(src["mitm_skip"])
    files = {}
    repo, branch = cfg["repository"], cfg["branch"]
    for p in paths:
        if source_dir:
            fp = os.path.join(source_dir, p)
            if not os.path.exists(fp):
                log("WARN local file missing: %s" % fp)
                files[p] = ""
                continue
            with open(fp, "r", encoding="utf-8-sig", errors="replace") as f:
                files[p] = f.read()
        else:
            files[p] = fetch(RAW_URL.format(repo=repo, branch=branch, path=p))
    return files


def clean_lines(text):
    """Trim + drop comments/blanks. Case is preserved: URL paths are case-sensitive;
    domain lines are lowercased later by their own parsers."""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        yield line


def parse_sgmodule(text):
    """Split a Surge/Shadowrocket module into {section_name: [content lines]}."""
    sections, cur = {}, None
    for raw in text.splitlines():
        s = raw.strip()
        if s.startswith("[") and s.endswith("]"):
            cur = s[1:-1].strip()
            sections.setdefault(cur, [])
            continue
        if cur is None or not s or s.startswith("#"):
            continue
        sections[cur].append(s)
    return sections


def convert_sgmodule_rules(lines, source):
    """[Rule] lines -> {reject: [(kind, val)], direct: [...]}; rest -> skipped."""
    out = {"reject": [], "direct": []}
    bad = []
    for s in lines:
        parts = [p.strip() for p in s.split(",")]
        if len(parts) < 2:
            bad.append(("malformed sgmodule rule: " + s, source))
            continue
        typ, val = parts[0].upper(), parts[1].lower()
        pol = parts[2].upper() if len(parts) > 2 else ""
        kind = SG_KIND.get(typ)
        if kind is None:
            bad.append(("unsupported sgmodule rule type %s: %s" % (typ, s), source))
            continue
        if pol not in ("REJECT", "DIRECT"):
            bad.append(("unsupported sgmodule policy %s: %s" % (pol or "(none)", s), source))
            continue
        if kind == "wildcard" and not valid_wildcard(val):
            bad.append(("unparseable sgmodule wildcard: " + s, source))
            continue
        if kind == "keyword" and not KEYWORD_RE.match(val):
            bad.append(("unparseable sgmodule keyword: " + s, source))
            continue
        if kind in ("exact", "suffix") and not valid_domain(val):
            bad.append(("unparseable sgmodule domain: " + s, source))
            continue
        out["reject" if pol == "REJECT" else "direct"].append((kind, val))
    return out, bad


def convert_sgmodule_rewrites(lines, source):
    """[URL Rewrite] 'pattern - action' -> QX '{pattern} url {action}' rules."""
    ok, bad = [], []
    for s in lines:
        m = SGM_RW_RE.match(s)
        if not m:
            bad.append(("sgmodule rewrite not in 'pattern - action' form: " + s, source))
            continue
        pattern, action = m.group(1), m.group(2).lower()
        if action not in SG_REWRITE_ACTIONS:
            bad.append(("sgmodule rewrite action not convertible (%s): %s" % (action, s), source))
            continue
        ok.append({"regex": pattern.replace("\\/", "/"), "raw": s, "action": action})
    return ok, bad


def load_extra_source(src):
    """Fetch an extra source, falling back to tools/<name>.sgmodule cache."""
    url = src.get("url")
    if url:
        try:
            return fetch(url)
        except Exception as e:  # noqa: BLE001 - fall back to cache, then skip
            log("WARN extra source %s download failed (%s), trying local cache" % (src.get("name"), e))
    cache = os.path.join(ROOT, "tools", src.get("name", "extra") + ".sgmodule")
    if os.path.exists(cache):
        with open(cache, "r", encoding="utf-8-sig", errors="replace") as f:
            return f.read()
    return None


# ---------------------------------------------------------------- domain classification

def valid_domain(d):
    if not d or "." not in d or len(d) > 253:
        return False
    return all(DOMAIN_LABEL_RE.match(l) for l in d.split("."))


def valid_wildcard(p):
    if not WILDCARD_CHARS_RE.match(p) or ".." in p or p.startswith(".") or p.endswith("."):
        return False
    return bool(re.search(r"[a-z0-9]", p))


def classify_domain(line):
    """-> (kind, value); kind in exact|suffix|wildcard|ip|url|path|skip."""
    if URL_SCHEME_RE.match(line):
        return "url", line
    if line.startswith("/"):
        return "path", line
    if IP_RE.match(line):
        return "ip", line
    if line.endswith("."):
        line = line[:-1]
    if not line:
        return "skip", line
    if "*" in line or "?" in line:
        if line.startswith("*.") and "*" not in line[2:] and "?" not in line[2:]:
            return ("suffix", line[2:]) if valid_domain(line[2:]) else ("skip", line)
        return ("wildcard", line) if valid_wildcard(line) else ("skip", line)
    return ("exact", line) if valid_domain(line) else ("skip", line)


def parse_domain_files(files, paths, bucket, url_pipeline=None):
    """bucket: dict with exact/suffix/wildcard/ip sets; returns (count, skips, dups).
    URL-shaped lines are optionally handed to url_pipeline(list)."""
    seen, dups = set(), 0
    skips = []
    for path in paths:
        for line in clean_lines(files.get(path, "")):
            low = line.lower()
            kind, val = classify_domain(low)
            if kind == "url":
                if url_pipeline is not None:
                    url_pipeline.append((low, path))
                else:
                    skips.append(("URL-shaped line in domain file (not converted): " + low, path))
                continue
            if kind == "skip":
                skips.append(("unparseable domain line: " + val, path))
                continue
            key = (kind, val)
            if key in seen:
                dups += 1
                continue
            seen.add(key)
            bucket[kind].add(val)
    return seen, skips, dups


# ---------------------------------------------------------------- URL rules

def parse_url(line):
    """-> {'host':..., 'path':...} or None. Scheme-less host/path mixes are accepted."""
    m = URL_PARTS_RE.match(line)
    if m:
        host = m.group(2).lower()
        path = (m.group(3) or "").rstrip("?")
        return {"host": host, "path": path}
    if "/" not in line:
        return None  # e.g. ".splash" substring patterns
    host, _, path = line.partition("/")
    return {"host": host.lower(), "path": "/" + path}


RE_SPECIAL = set(".^$*+?()[]{}|\\")


def re_lit(ch):
    return "\\" + ch if ch in RE_SPECIAL else ch


def escape_host(h):
    out = []
    for ch in h:
        if ch == "*":
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        else:
            out.append(re_lit(ch))
    return "".join(out)


def escape_path(p):
    out = []
    for ch in p:
        out.append(".*" if ch == "*" else re_lit(ch))
    return "".join(out)


def url_to_regex(u):
    """Full URL -> QX rewrite regex. Returns None for empty-path URLs (degrade to host rule)."""
    path = u["path"]
    if not path or path == "/":
        return None
    tail = "" if path.endswith("*") else "(?:\\?|$)"
    return "^https?://%s%s%s" % (escape_host(u["host"]), escape_path(path), tail)


def build_url_rules(files, paths):
    """Parse URL source files -> list of dicts {host, path, raw, file} preserving order."""
    rules, unparsed = [], []
    for path in paths:
        for line in clean_lines(files.get(path, "")):
            if line.startswith("/"):
                rules.append({"host": "", "path": line, "raw": line, "file": path})
                continue
            u = parse_url(line)
            if u is None:
                unparsed.append((line, path))
                continue
            u["raw"], u["file"] = line, path
            rules.append(u)
    return rules, unparsed


def host_wildcard_match(host, pattern):
    return fnmatch.fnmatchcase(host, pattern)


def make_whitelist_predicates(wl_domains, wl_urls):
    wl_exact = wl_domains["exact"]
    wl_suffix = wl_domains["suffix"]
    wl_wild = sorted(wl_domains["wildcard"])
    wl_keywords = wl_domains["keyword"]
    generic_paths = [u["path"].rstrip("*") for u in wl_urls if not u["host"]]
    hosted = [u for u in wl_urls if u["host"]]

    def domain_whitelisted(v):
        if v in wl_exact:
            return True
        for s in wl_suffix:
            if v == s or v.endswith("." + s):
                return True
        if any(k in v for k in wl_keywords):
            return True
        return any(host_wildcard_match(v, p) for p in wl_wild)

    def url_whitelisted(host, path):
        for u in hosted:
            wh = u["host"]
            if wh != host and not ("*" in wh and host_wildcard_match(host, wh)):
                continue
            if path.startswith(u["path"].rstrip("*")):
                return True
        return any(path.startswith(gp) for gp in generic_paths)

    return domain_whitelisted, url_whitelisted


# ---------------------------------------------------------------- output

EXTRA_NOTES = []


def header(lines_extra):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = [
        "# Generated by jinx-rules-qx converter. DO NOT EDIT BY HAND.",
        "# Source: https://github.com/VME98/jinx-rules",
    ]
    for note in EXTRA_NOTES:
        out.append("# Merged source: " + note)
    out += ["# " + l for l in lines_extra]
    out.append("# Generated: " + now)
    return out


def fmt_rule(kind, value, policy):
    return "%s, %s, %s" % (KIND_TYPE[kind], value, policy)


def write_filter(path, commit, wl, bl):
    lines = header([
        "Upstream commit: %s" % commit,
        "Whitelist (direct) rules come first on purpose; QX matches top-down.",
    ])
    blocks = []
    for bucket, policy, title in ((wl, "direct", "WHITELIST"), (bl, "reject", "BLACKLIST")):
        lines.append("# ==== %s (%s) ====" % (title, policy))
        n = 0
        for kind in ("exact", "suffix", "wildcard", "keyword", "ip"):
            for v in sorted(bucket[kind]):
                lines.append(fmt_rule(kind, v, policy))
                n += 1
        blocks.append(n)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    return blocks


def write_rewrite(path, commit, rules):
    lines = header([
        "Upstream commit: %s" % commit,
        "URL regex rules; subscribe under [rewrite_remote].",
        "HTTPS rewrites require MITM; keep hosts from jinx-mitm-skip.txt out of your [mitm] hostname.",
    ])
    lines.append("")
    lines.append("[rewrite_local]")
    for r in rules:
        lines.append("%s url %s" % (r["regex"], r.get("action", "reject-200")))
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    return len(rules)


def write_mitm(path, commit, entries):
    lines = header([
        "Upstream commit: %s" % commit,
        "Append the entries below AFTER your own [mitm] hostname value (comma separated),",
        "or remove them from an existing hostname list. Never let automation rewrite [mitm].",
    ])
    lines += sorted(entries)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    return len(entries)


def write_unsupported(path, skips):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for reason, src in skips:
            f.write("%s :: %s\n" % (reason, src))
    return len(skips)


# ---------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(description="Convert Jinx rules to Quantumult X format")
    ap.add_argument("--source-dir", help="read upstream files from a local checkout instead of downloading")
    ap.add_argument("--commit", help="upstream commit hash for the file headers")
    ap.add_argument("--out-dir", default=OUT_DIR)
    args = ap.parse_args(argv)

    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    safe_mode = bool(cfg.get("safe_mode", True))
    convert_generic_path = bool(cfg.get("convert_generic_path", False)) and not safe_mode
    convert_unknown_url = bool(cfg.get("convert_unknown_url", False)) and not safe_mode
    convert_regex = bool(cfg.get("convert_regex", False)) and not safe_mode
    dedup = bool(cfg.get("deduplicate", True))
    repo, branch = cfg["repository"], cfg["branch"]

    if args.source_dir:
        commit = args.commit or "local-test"
    else:
        commit = args.commit or upstream_commit(repo, branch)
    log("upstream: %s@%s (commit %s)" % (repo, branch, commit))

    files = load_sources(cfg, args.source_dir)

    wl, bl = new_bucket(), new_bucket()
    extra_bl_urls = []  # URL lines mixed into domain files, routed through the URL pipeline
    wl_doms, wl_skips, wl_dups = parse_domain_files(
        files, cfg["sources"]["domain"]["whitelist"], wl)
    bl_doms, bl_skips, bl_dups = parse_domain_files(
        files, cfg["sources"]["domain"]["blacklist"], bl, url_pipeline=extra_bl_urls)

    # merge extra sources (e.g. Shadowrocket modules) into the same buckets
    extra_rewrites, extra_bad, sg_stats = [], [], []
    EXTRA_NOTES.clear()
    for src in cfg.get("extra_sources", []):
        name = src.get("name", "extra")
        text = load_extra_source(src)
        if text is None:
            log("WARN extra source %s unavailable, skipped" % name)
            continue
        if src.get("type", "sgmodule") != "sgmodule":
            log("WARN extra source %s: unknown type, skipped" % name)
            continue
        EXTRA_NOTES.append("%s (%s)" % (name, src.get("url", "local")))
        sections = parse_sgmodule(text)
        if src.get("include_rule_section", True):
            conv, bad = convert_sgmodule_rules(sections.get("Rule", []), name)
            for kind, val in conv["direct"]:
                wl[kind].add(val)
            for kind, val in conv["reject"]:
                bl[kind].add(val)
            sg_stats.append("%s: +%d reject, +%d direct domain rules"
                            % (name, len(conv["reject"]), len(conv["direct"])))
            extra_bad += bad
        if src.get("include_url_rewrite", True):
            conv, bad = convert_sgmodule_rewrites(sections.get("URL Rewrite", []), name)
            extra_rewrites += conv
            sg_stats.append("%s: +%d URL rewrite rules" % (name, len(conv)))
            extra_bad += bad
        for sec, why in (("Body Rewrite", "Surge jq body rewrite, QX has no equivalent"),
                         ("Script", "remote script action, keep in Shadowrocket/Surge or port by hand"),
                         ("MITM", "MITM hostname list, must stay manual")):
            n = len(sections.get(sec, []))
            if n:
                extra_bad.append(("[%s] not converted (%s): %d entries" % (sec, why, n), name))
    domain_whitelisted, url_whitelisted = make_whitelist_predicates(
        wl, build_url_rules(files, cfg["sources"]["url"]["whitelist"])[0])

    # blacklist domains suppressed by whitelist
    bl_removed_by_wl = 0
    for kind in ("exact", "suffix", "wildcard", "keyword", "ip"):
        keep = set()
        for v in bl[kind]:
            if kind == "keyword":
                keep.add(v)  # substring rules cannot be checked as a single host
                continue
            if domain_whitelisted(v):
                bl_removed_by_wl += 1
            else:
                keep.add(v)
        bl[kind] = keep

    # URL rules
    bl_urls, bl_unparsed = build_url_rules(files, cfg["sources"]["url"]["blacklist"])
    for line, path in extra_bl_urls:  # URLs found inside domain files
        u = parse_url(line)
        if u is not None:
            u["raw"], u["file"] = line, path
            bl_urls.append(u)
        else:
            bl_unparsed.append((line, path))
    wl_urls, wl_unparsed = build_url_rules(files, cfg["sources"]["url"]["whitelist"])

    skips = list(bl_skips) + list(wl_skips) + list(extra_bad)
    skips += [("unparseable URL (convert_unknown_url=false): " + l, f) for l, f in bl_unparsed]
    skips += [("unparseable whitelist URL (ignored): " + l, f) for l, f in wl_unparsed]

    def covered_by_domain(host):
        if host in bl["exact"]:
            return True
        if any(host == s or host.endswith("." + s) for s in bl["suffix"]):
            return True
        return any(host_wildcard_match(host, p) for p in bl["wildcard"])

    rewrite_rules, degraded = [], []
    stats = {"wl_url_excluded": 0, "dead_domain_covered": 0, "generic_path": 0,
             "regex_like": 0, "unknown_url": 0, "dup_rewrite": 0}
    seen_regex = set()
    for r in extra_rewrites:  # from merged sgmodules, already in QX syntax
        if not dedup or r["regex"] not in seen_regex:
            seen_regex.add(r["regex"])
            rewrite_rules.append(r)
    for u in bl_urls:
        host, path = u["host"], u["path"]
        if not host:  # generic path rule without any host context
            stats["generic_path"] += 1
            if convert_generic_path:
                regex = "^https?://[^/]*%s(?:\\?|$)" % escape_path(path)
            else:
                skips.append(("generic path rule without host (safe_mode): " + u["raw"], u["file"]))
                continue
        else:
            if domain_whitelisted(host):
                stats["wl_url_excluded"] += 1
                continue
            if url_whitelisted(host, path):
                stats["wl_url_excluded"] += 1
                continue
            if covered_by_domain(host):
                stats["dead_domain_covered"] += 1
                continue
            if any(c in path or c in host for c in REGEX_METACHARS):
                stats["regex_like"] += 1
                if not convert_regex:
                    skips.append(("regex-like URL rule (safe_mode): " + u["raw"], u["file"]))
                    continue
            regex = url_to_regex(u) if URL_SCHEME_RE.match(u["raw"]) or "/" in u["raw"] else None
            if regex is None:  # empty-path URL -> degrade to a filter host rule
                bare = host.split(":")[0]
                kind = "wildcard" if ("*" in bare or "?" in bare) else "exact"
                if not dedup or (kind, bare) not in bl[kind]:
                    bl[kind].add(bare)
                degraded.append(u["raw"])
                continue
        if not dedup or regex not in seen_regex:
            seen_regex.add(regex)
            rewrite_rules.append({"regex": regex, "raw": u["raw"]})
        else:
            stats["dup_rewrite"] += 1

    # mitm skip list: keep original syntax (exact domains and *.wildcard both legal in [mitm])
    mitm = set()
    for path in cfg["sources"]["mitm_skip"]:
        for line in clean_lines(files.get(path, "")):
            low = line.lower()
            kind, val = classify_domain(low)
            if kind in ("exact", "suffix", "wildcard"):
                mitm.add("*." + val if kind == "suffix" else low)
            elif kind != "skip":
                skips.append(("unexpected mitm_skip line: " + low, path))

    os.makedirs(args.out_dir, exist_ok=True)
    # The single root-level filter file is the primary deliverable (subscribed in QX);
    # generated/ holds the optional extras (rewrite / mitm skip / audit log).
    single_path = os.path.join(ROOT, cfg.get("single_filter_output", "jinx-adblock-qx.list"))
    wl_n, bl_n = write_filter(single_path, commit, wl, bl)
    rw_n = write_rewrite(os.path.join(args.out_dir, "jinx-qx-rewrite.conf"), commit, rewrite_rules)
    mitm_n = write_mitm(os.path.join(args.out_dir, "jinx-mitm-skip.txt"), commit, mitm)
    skip_n = write_unsupported(os.path.join(args.out_dir, "unsupported.log"), skips)

    log("== summary ==")
    log("filter:  %d rules (whitelist %d, blacklist %d)" % (wl_n + bl_n, wl_n, bl_n))
    log("rewrite: %d rules (+%d degraded to host rules)" % (rw_n, len(degraded)))
    log("mitm skip: %d" % mitm_n)
    log("unsupported: %d" % skip_n)
    log("dedup: %d domain lines (%d wl, %d bl); %d rewrite dups" %
        (wl_dups + bl_dups, wl_dups, bl_dups, stats["dup_rewrite"]))
    log("url excluded by whitelist: %d, covered by domain rules: %d, generic path skipped: %d" %
        (stats["wl_url_excluded"], stats["dead_domain_covered"], stats["generic_path"]))
    log("extra sources: " + ("; ".join(sg_stats) if sg_stats else "none"))
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
