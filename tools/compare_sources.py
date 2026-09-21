#!/usr/bin/env python3
"""Measure the overlap between VME98/jinx-rules and uxudjs/Shadowrocket's
fuck_apps_ad_sr.sgmodule, straight from their raw sources (independent of this
repo's generated output). Dev tool, not part of the CI pipeline.

Usage: python tools/compare_sources.py
"""

import os
import re
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SGM_URL = ("https://raw.githubusercontent.com/uxudjs/Shadowrocket/refs/heads/main"
           "/modules/fuck_apps_ad_sr.sgmodule")
JINX = "https://raw.githubusercontent.com/VME98/jinx-rules/master/rules/"
JINX_DOMAIN_FILES = ["domain_blacklist.txt", "blacklist.txt", "blacklist_wildcard.txt"]
JINX_URL_FILES = ["url_blacklist.txt", "url_blacklist_domain_paths.txt"]


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "jinx-rules-qx"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def fetch_or_cache(url, cache_name):
    cache = os.path.join(ROOT, "tools", cache_name)
    if os.path.exists(cache):
        with open(cache, encoding="utf-8") as f:
            return f.read()
    print("downloading %s" % url, file=sys.stderr)
    text = fetch(url)
    with open(cache, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return text


def sections(text):
    cur, out, ordered = None, {}, []
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("[") and s.endswith("]"):
            cur = s[1:-1]
            out.setdefault(cur, [])
            ordered.append(cur)
            continue
        if cur and s and not s.startswith("#"):
            out[cur].append(s)
    return out


def jinx_domains():
    exact, suffix, wildcard = set(), set(), set()
    for fn in JINX_DOMAIN_FILES:
        for ln in fetch_or_cache(JINX + fn, "jinx_" + fn).splitlines():
            d = ln.strip().lower()
            if not d or d.startswith("#") or "://" in d or d.startswith("/"):
                continue
            if d.startswith("*."):
                suffix.add(d[2:])
            elif "*" in d or "?" in d:
                wildcard.add(d)
            elif "." in d:
                exact.add(d.rstrip("."))
    return exact, suffix, wildcard


def jinx_urls():
    out = set()
    for fn in JINX_URL_FILES:
        for ln in fetch_or_cache(JINX + fn, "jinx_" + fn).splitlines():
            u = ln.strip().lower()
            if u.startswith("http://") or u.startswith("https://"):
                out.add(u)
    return out


def norm_rx(rx):
    return re.sub(r"^\\\^", "^", rx.replace("\\/", "/")).rstrip("\\")


def main():
    secs = sections(fetch_or_cache(SGM_URL, "fuck_apps_ad_sr.sgmodule"))

    sg = {"exact": set(), "suffix": set(), "wildcard": set(), "keyword": set(), "ip": set(),
          "direct": set()}
    for s in secs.get("Rule", []):
        parts = [p.strip() for p in s.split(",")]
        if len(parts) < 3:
            continue
        k = {"DOMAIN": "exact", "DOMAIN-SUFFIX": "suffix", "DOMAIN-WILDCARD": "wildcard",
             "DOMAIN-KEYWORD": "keyword", "IP-CIDR": "ip"}.get(parts[0].upper())
        if not k:
            continue
        (sg["direct"] if parts[2].upper() == "DIRECT" else sg[k]).add(parts[1].lower())

    j_exact, j_suffix, j_wild = jinx_domains()
    print("jinx domains: exact=%d suffix=%d wildcard=%d" % (len(j_exact), len(j_suffix), len(j_wild)))

    print("\n== sgmodule REJECT rules duplicated by jinx (same rule type) ==")
    print("  DOMAIN          %d/%d %s" % (len(sg["exact"] & j_exact), len(sg["exact"]),
                                          sorted(sg["exact"] & j_exact)))
    print("  DOMAIN-SUFFIX   %d/%d %s" % (len(sg["suffix"] & j_suffix), len(sg["suffix"]),
                                          sorted(sg["suffix"] & j_suffix)))
    print("  DOMAIN-WILDCARD %d/%d %s" % (len(sg["wildcard"] & j_wild), len(sg["wildcard"]),
                                          sorted(sg["wildcard"] & j_wild)))
    print("  IP-CIDR         no jinx equivalent (jinx ships no IP rules)")

    print("\n== sgmodule DOMAIN-KEYWORD rules: host rules in jinx containing the keyword ==")
    for kw in sorted(sg["keyword"]):
        hits = [v for v in j_exact if kw in v] + [v for v in j_suffix if kw in v] \
            + [v for v in j_wild if kw in v]
        print("  %-14s jinx-hits=%-3d %s" % (kw, len(hits), hits[:4]))

    print("\n== sgmodule URLs / domains whose host is already fully blocked by jinx ==")
    def blocked(host):
        h = host.lstrip("*.").lower()
        if h in j_exact:
            return True
        if any(h == s or h.endswith("." + s) for s in j_suffix):
            return True
        return any(re.fullmatch(w.replace("*", ".*").replace("?", "."), h) for w in j_wild)

    sg_rx = {norm_rx(m.group(1)): m.group(2) for m in
             (re.match(r"^(\S+)\s+-\s+(\S+)$", s) for s in secs.get("URL Rewrite", [])) if m}
    j_urls = jinx_urls()
    same = 0
    for rx, act in sg_rx.items():
        for u in j_urls:
            u_rx = re.escape(u).replace(r"\*", ".*")
            if u_rx.rstrip("$") in rx or rx in u_rx:
                same += 1
                break
    print("  sgmodule rewrite rules: %d, byte-similar to a jinx URL rule: %d" % (len(sg_rx), same))

    print("\n== sgmodule sections that cannot be converted to QX ==")
    for sec in ("Body Rewrite", "Script", "MITM"):
        print("  [%s] entries=%d" % (sec, len(secs.get(sec, []))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
