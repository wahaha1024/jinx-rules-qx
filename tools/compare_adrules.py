#!/usr/bin/env python3
"""Accurate diff: AdRules jinx adapter (Surge sgmodule) vs our QX output.

Usage: python tools/compare_adrules.py
Dev tool, not part of CI.
"""
import re
from collections import Counter

ROOT = "E:/GLM/jinx-rules-qx/"
SGM = ROOT + "tools/adrules_jinx.sgmodule"
OURS = ROOT + "jinx-adblock-qx.list"
OUR_RW = ROOT + "generated/jinx-qx-rewrite.conf"
OUR_MITM = ROOT + "generated/jinx-mitm-required.txt"

PRECISION_HOSTS = {
    "sdk.e.qq.com", "mi.gdt.qq.com", "v2mi.gdt.qq.com", "win.gdt.qq.com",
    "v.gdt.qq.com", "v3.gdt.qq.com",
    "api-access.pangolin-sdk-toutiao.com", "api-access.pangolin-sdk-toutiao1.com",
    "api-access.pangolin-sdk-toutiao-b.com",
}


def read(p):
    with open(p, encoding="utf-8", errors="replace") as f:
        return f.read().splitlines()


def sections(lines):
    cur, out = None, {}
    for ln in lines:
        s = ln.strip()
        if s.startswith("[") and s.endswith("]"):
            cur = s[1:-1]
            out.setdefault(cur, [])
            continue
        if cur and s and not s.startswith("#"):
            out[cur].append(s)
    return out


def strip_lead_lookaheads(rx):
    s = rx
    if s.startswith("^"):
        s = s[1:]
    while s.startswith("(?!"):
        depth, j = 0, 0
        while j < len(s):
            c = s[j]
            if c == "\\":
                j += 2
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        s = s[j + 1:]
    return s


def unesc(x):
    for a, b in (("\\/", "/"), ("\\.", "."), ("\\-", "-"), ("\\?", "?"), ("\\_", "_")):
        x = x.replace(a, b)
    return x.replace("\\", "")


def target(rx):
    """regex -> (host, path-prefix) or None. Host may keep wildcards (img[^/]*.x.com)."""
    s = strip_lead_lookaheads(rx).replace("\\/", "/")
    i = s.find("://")
    if i == -1:
        return None
    rest = s[i + 3:]
    if rest.startswith("(?:"):
        rest = rest[3:]
    j, in_class = 0, False
    while j < len(rest):
        c = rest[j]
        if c == "\\":
            j += 2
            continue
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif not in_class and c in "/()|":
            break
        j += 1
    host = rest[:j]
    k = j
    for pat in (r"\(\?::\[0-9\]\+\)\?", r"\(\?::\d\+\)\?"):
        m2 = re.match(pat, rest[k:])
        if m2:
            k += m2.end()
            break
    path = ""
    if k < len(rest) and rest[k] == "/":
        e = k
        while e < len(rest) and rest[e] not in "(|$*":
            e += 1
        path = rest[k:e]
    host = unesc(host).replace("[^/]*", "*").replace("[^/]", "?").strip("()")
    if not host or "(" in host:
        return None
    return host, unesc(path).rstrip(").")


def main():
    secs = sections(read(SGM))

    ar_rules = []
    for s in secs.get("URL Rewrite", []):
        m = re.match(r"^(\S+)\s+-\s+(\S+)$", s)
        if m:
            ar_rules.append((m.group(1), m.group(2)))

    my_rules = []
    for ln in read(OUR_RW):
        m = re.match(r"^(\S+)\s+url\s+(\S+)", ln)
        if m and not ln.startswith("#"):
            my_rules.append((m.group(1), m.group(2)))

    my_keys = [k for k in (target(r) for r, _ in my_rules) if k]

    import fnmatch

    def covered(host, path):
        for h, p in my_keys:
            if h != host and not ("*" in h or "?" in h) :
                continue
            if ("*" in h or "?" in h) and not fnmatch.fnmatchcase(host, h):
                continue
            if not path or not p:
                return True
            if p.startswith(path) or path.startswith(p):
                return True
        return False

    matched, precision, extra = [], [], []
    for r, a in ar_rules:
        t = target(r)
        if not t:
            continue
        host, path = t
        if host in PRECISION_HOSTS or any(host.endswith("." + h) for h in PRECISION_HOSTS):
            precision.append((host, path, a))
        elif covered(host, path):
            matched.append((host, path, a))
        else:
            extra.append((host, path, a))

    print("== URL Rewrite (AdRules %d rules) ==" % len(ar_rules))
    print("  precision-layer (GDT/Pangle 9 hosts): %d" % len(precision))
    for h, p, a in precision:
        print("      %-42s %-45s %s" % (h, p[:45], a))
    print("  covered by our rewrite file: %d" % len(matched))
    print("  NOT covered (their extras): %d" % len(extra))
    for h, p, a in extra[:30]:
        print("      %-42s %-45s %s" % (h, p[:45], a))
    print("  our rewrite rules: %d, of which matched by theirs: -" % len(my_rules))

    # ---- domain rules
    ar_dom = {"exact": set(), "wild": set()}
    for s in secs.get("Rule", []):
        parts = [p.strip() for p in s.split(",")]
        if len(parts) < 3 or parts[0].upper() not in ("DOMAIN", "DOMAIN-WILDCARD"):
            continue
        if parts[2].upper() != "REJECT":
            continue
        ar_dom["exact" if parts[0].upper() == "DOMAIN" else "wild"].add(parts[1].lower())

    mine = {"exact": set(), "suffix": set(), "wild": set(), "keyword": set()}
    for ln in read(OURS):
        if ln.startswith("#"):
            continue
        parts = [p.strip() for p in ln.split(",")]
        if len(parts) < 3 or parts[2] != "reject":
            continue
        k = {"host": "exact", "host-suffix": "suffix", "host-wildcard": "wild",
             "host-keyword": "keyword"}.get(parts[0])
        if k:
            mine[k].add(parts[1])

    def my_covers(v):
        if v in mine["exact"]:
            return "exact"
        for s in mine["suffix"]:
            if v == s or v.endswith("." + s):
                return "suffix"
        import fnmatch
        for w in mine["wild"]:
            if fnmatch.fnmatchcase(v, w):
                return "wild"
        if any(k in v for k in mine["keyword"]):
            return "keyword"
        return None

    ar_all = ar_dom["exact"] | ar_dom["wild"]
    print("\n== domain rules ==")
    print("  AdRules reject domains: %d (exact %d + wildcard %d)"
          % (len(ar_all), len(ar_dom["exact"]), len(ar_dom["wild"])))
    print("  ours reject: %d (exact %d + suffix %d + wildcard %d + keyword %d)"
          % (sum(len(v) for v in mine.values()), len(mine["exact"]), len(mine["suffix"]),
             len(mine["wild"]), len(mine["keyword"])))
    only_ar = []
    for v in sorted(ar_all):
        if not my_covers(v):
            only_ar.append(v)
    print("  AdRules-only (we don't cover): %d %s" % (len(only_ar), only_ar))

    mine_all = set()
    for k, vals in mine.items():
        mine_all |= vals
    only_mine = []
    for v in sorted(mine_all):
        # covered by AdRules? exact match, or their wildcard covers it
        if v in ar_all:
            continue
        if any(re.fullmatch(w.replace("*", ".*").replace("?", "."), v) for w in ar_dom["wild"]):
            continue
        if any(v == e or v.endswith("." + e) for e in ar_dom["exact"]):
            continue
        only_mine.append(v)
    print("  ours-only (they don't cover): %d" % len(only_mine))
    cnt = Counter()
    for v in only_mine:
        cnt["keyword" if v in mine["keyword"] else
            ("ip" if "/" in v else "-".join(["w"]))] += 1
    # show a categorized sample
    sample = Counter()
    for v in only_mine:
        if v in mine["keyword"]:
            sample["host-keyword"] += 1
        elif "/" in v:
            sample["ip-cidr"] += 1
        elif "*" in v:
            sample["wildcard"] += 1
        elif v in mine["suffix"]:
            sample["suffix"] += 1
        else:
            sample["exact"] += 1
    print("  ours-only breakdown:", dict(sample))

    print("\n== other AdRules sections ==")
    print("  [Host]:", secs.get("Host", []))
    for s in secs.get("Rule", []):
        if s.upper().startswith("AND"):
            print("  AND rule:", s[:110])
    mitm_line = ""
    for s in secs.get("MITM", []):
        if s.lower().startswith("hostname"):
            mitm_line = s
            break
    ar_mitm_pos = [p.strip().replace("%APPEND%", "").strip()
                   for p in mitm_line.split("=", 1)[-1].split(",")
                   if p.strip() and not p.strip().startswith("-")]
    my_mitm = {ln.strip() for ln in read(OUR_MITM)
               if ln.strip() and not ln.startswith("#")}
    print("  [MITM] positive hosts: %d, ours (jinx-mitm-required.txt): %d"
          % (len(ar_mitm_pos), len(my_mitm)))
    same = {h for h in ar_mitm_pos if h in my_mitm}
    print("  identical MITM host entries: %d" % len(same))
    import fnmatch
    covered = set()
    for h in ar_mitm_pos:
        for m in my_mitm:
            if m == h or ("*" in m and fnmatch.fnmatchcase(h, m)):
                covered.add(h)
                break
    print("  AdRules MITM hosts already covered by ours: %d" % len(covered))
    only_theirs = [h for h in ar_mitm_pos if h not in covered]
    print("  AdRules-only MITM hosts: %d %s" % (len(only_theirs), only_theirs[:12]))


if __name__ == "__main__":
    main()
