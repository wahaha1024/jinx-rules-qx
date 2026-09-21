"""Unit tests for the converter's parsing and classification logic."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "converter"))

import convert  # noqa: E402


def test_classify_exact():
    assert convert.classify_domain("ads.example.com") == ("exact", "ads.example.com")


def test_classify_suffix_wildcard():
    assert convert.classify_domain("*.example.com") == ("suffix", "example.com")


def test_classify_mid_wildcard():
    kind, val = convert.classify_domain("p*-ad.adkwai.com")
    assert kind == "wildcard"
    assert val == "p*-ad.adkwai.com"


def test_classify_url_line():
    assert convert.classify_domain("https://example.com/ad.js")[0] == "url"
    assert convert.classify_domain("http://a.b/c?d")[0] == "url"


def test_classify_path_line():
    assert convert.classify_domain("/api/ad")[0] == "path"


def test_classify_ip():
    assert convert.classify_domain("1.2.3.4") == ("ip", "1.2.3.4")
    assert convert.classify_domain("10.0.0.0/8") == ("ip", "10.0.0.0/8")


def test_classify_trailing_dot():
    assert convert.classify_domain("zalo-ads-480-td.") == ("skip", "zalo-ads-480-td")


def test_classify_invalid():
    assert convert.classify_domain("wpad")[0] == "skip"
    assert convert.classify_domain(".splash")[0] == "skip"


def test_url_parse_full():
    u = convert.parse_url("https://www.dongchedi.com/motor/ad")
    assert u == {"host": "www.dongchedi.com", "path": "/motor/ad"}


def test_url_parse_query_only():
    u = convert.parse_url("https://ynuf.aliapp.org/savewb.json?")
    assert u == {"host": "ynuf.aliapp.org", "path": "/savewb.json"}


def test_url_parse_wildcard_host():
    u = convert.parse_url("https://img*.360buyimg.com/jddjadvertise")
    assert u["host"] == "img*.360buyimg.com"
    assert u["path"] == "/jddjadvertise"


def test_url_parse_hostless_path():
    u = convert.parse_url("/splash")
    assert u == {"host": "", "path": "/splash"}


def test_url_regex_basic():
    r = convert.url_to_regex({"host": "a.b.com", "path": "/x/y"})
    assert r == r"^https?://a\.b\.com(?::\d+)?/x/y(?:\?|$)"


def test_url_regex_port_tolerant():
    r = convert.url_to_regex({"host": "r.inews.qq.com", "path": "/getNewsRemoteConfig"})
    assert "(?::\\d+)?" in r
    import re
    assert re.search(r, "https://r.inews.qq.com/getNewsRemoteConfig")
    assert re.search(r, "https://r.inews.qq.com:8443/getNewsRemoteConfig")


def test_host_from_regex():
    assert convert.host_from_regex(r"^https?://api\.b\.com(?::\d+)?/x") == "api.b.com"
    assert convert.host_from_regex(r"^https?://.*api\.moji\.com/x") == "*api.moji.com"
    assert convert.host_from_regex(r"^https?://tnc.*zijieapi\.com/x") == "tnc*zijieapi.com"
    assert convert.host_from_regex(r"^https?://a\.b\.com/x") == "a.b.com"


def test_in_mitm_skip():
    entries = {"*.apple.com", "ccsp-egmas.sf-express.com", "tnc*zijieapi.com"}
    assert convert.in_mitm_skip("a.b.apple.com", entries)
    assert convert.in_mitm_skip("ccsp-egmas.sf-express.com", entries)
    assert not convert.in_mitm_skip("other.com", entries)


def test_url_regex_keeps_case():
    r = convert.url_to_regex({"host": "a.b.com", "path": "/getAdverList"})
    assert "/getAdverList" in r


def test_url_regex_empty_path_degrades():
    assert convert.url_to_regex({"host": "a.b.com", "path": ""}) is None
    assert convert.url_to_regex({"host": "a.b.com", "path": "/"}) is None


def test_url_regex_wildcard_path():
    r = convert.url_to_regex({"host": "api.dongdianqiu.com", "path": "/*/startup"})
    assert ".*" in r and r.endswith("/startup(?:\\?|$)")


def test_escape_host_mid_wildcard():
    assert convert.escape_host("p*-ad.adkwai.com") == r"p[^/]*\-ad\.adkwai\.com".replace("\\-", "-") \
        or convert.escape_host("p*-ad.adkwai.com") == r"p[^/]*-ad\.adkwai\.com"


def test_clean_lines():
    text = "# c\n\n  ads.com  \n; semi\nx.com"
    assert list(convert.clean_lines(text)) == ["ads.com", "x.com"]


def test_clean_lines_case_preserved():
    assert list(convert.clean_lines("GetAdverList")) == ["GetAdverList"]


def test_mitm_suffix_groups():
    hosts = {"a.x.com", "b.x.com", "c.x.com", "solo.y.com", "two.label"}
    groups = convert.mitm_suffix_groups(hosts, min_group=3)
    assert groups == {"x.com": ["a.x.com", "b.x.com", "c.x.com"]}


def test_fold_mitm_hosts_requires_opt_in():
    hosts = {"a.x.com", "b.x.com", "c.x.com"}
    folded, removed = convert.fold_mitm_hosts(hosts, set(), [])
    assert folded == hosts and removed == 0  # no opt-in -> nothing widens


def test_fold_mitm_hosts_folds_when_asked():
    hosts = {"a.x.com", "b.x.com", "c.x.com", "keep.y.com"}
    folded, removed = convert.fold_mitm_hosts(hosts, set(), ["x.com"])
    assert "*.x.com" in folded
    assert "a.x.com" not in folded
    assert "keep.y.com" in folded
    assert removed == 3


def test_fold_mitm_hosts_respects_skip():
    hosts = {"a.x.com", "b.x.com", "c.x.com"}
    folded, removed = convert.fold_mitm_hosts(hosts, {"b.x.com"}, ["x.com"])
    assert removed == 0  # a must-not-decrypt host lives in the group
    assert folded == hosts


def test_host_from_regex_strips_port():
    assert convert.host_from_regex(r"^https?://daijia\.kuaidadi\.com:443/gateway") is None or \
        convert.host_from_regex(r"^https?://daijia\.kuaidadi\.com:443/gateway") == \
        "daijia.kuaidadi.com"


def test_validate_outputs_catches_duplicates(tmp_path):
    f = tmp_path / "f.list"
    f.write_text("host, a.com, reject\nhost, a.com, reject\n", encoding="utf-8")
    rw = tmp_path / "r.conf"
    rw.write_text("[rewrite_local]\n^x url reject-200\n", encoding="utf-8")
    m1 = tmp_path / "m1.txt"; m1.write_text("a.com\n", encoding="utf-8")
    m2 = tmp_path / "m2.txt"; m2.write_text("b.com\n", encoding="utf-8")
    import pytest
    with pytest.raises(SystemExit):
        convert.validate_outputs(str(f), str(rw), str(m1), str(m2))


def test_validate_outputs_catches_bad_order(tmp_path):
    f = tmp_path / "f.list"
    f.write_text("host, a.com, reject\nhost, b.com, direct\n", encoding="utf-8")
    rw = tmp_path / "r.conf"
    rw.write_text("[rewrite_local]\n^x url reject-200\n", encoding="utf-8")
    m1 = tmp_path / "m1.txt"; m1.write_text("a.com\n", encoding="utf-8")
    m2 = tmp_path / "m2.txt"; m2.write_text("b.com\n", encoding="utf-8")
    import pytest
    with pytest.raises(SystemExit):
        convert.validate_outputs(str(f), str(rw), str(m1), str(m2))


def test_validate_outputs_catches_bad_regex(tmp_path):
    f = tmp_path / "f.list"
    f.write_text("host, a.com, direct\n", encoding="utf-8")
    rw = tmp_path / "r.conf"
    rw.write_text("[rewrite_local]\n^https?://a.com/(unclosed url reject-200\n", encoding="utf-8")
    m1 = tmp_path / "m1.txt"; m1.write_text("a.com\n", encoding="utf-8")
    m2 = tmp_path / "m2.txt"; m2.write_text("b.com\n", encoding="utf-8")
    import pytest
    with pytest.raises(SystemExit):
        convert.validate_outputs(str(f), str(rw), str(m1), str(m2))


def test_validate_outputs_passes_clean(tmp_path):
    f = tmp_path / "f.list"
    f.write_text("host, a.com, direct\nhost, b.com, reject\n", encoding="utf-8")
    rw = tmp_path / "r.conf"
    rw.write_text("[rewrite_local]\n^https?://a\\.b/c url reject-dict\n", encoding="utf-8")
    m1 = tmp_path / "m1.txt"; m1.write_text("a.com\n", encoding="utf-8")
    m2 = tmp_path / "m2.txt"; m2.write_text("b.com\n", encoding="utf-8")
    n_filter, n_rw = convert.validate_outputs(str(f), str(rw), str(m1), str(m2))
    assert (n_filter, n_rw) == (2, 1)


def test_whitelist_domain_match():
    wl = {"exact": {"a.com"}, "suffix": {"safe.com"}, "wildcard": {"cm-10-*.getui.com"},
          "keyword": set(), "ip": set()}
    dw, _ = convert.make_whitelist_predicates(wl, [])
    assert dw("a.com")
    assert dw("sub.safe.com")
    assert dw("cm-10-77.getui.com")
    assert not dw("b.com")


def test_sgmodule_rule_conversion():
    conv, bad = convert.convert_sgmodule_rules([
        "DOMAIN,ads.example.com,REJECT",
        "DOMAIN-SUFFIX,tracker.io,REJECT",
        "DOMAIN-WILDCARD,*-ad.*,REJECT",
        "DOMAIN-KEYWORD,umeng,REJECT",
        "IP-CIDR,1.2.3.4/32,REJECT",
        "DOMAIN-WILDCARD,adblock.*,DIRECT",
        "DOMAIN,bad-policy.com,PROXY",
    ], "test")
    assert ("exact", "ads.example.com") in conv["reject"]
    assert ("suffix", "tracker.io") in conv["reject"]
    assert ("wildcard", "*-ad.*") in conv["reject"]
    assert ("keyword", "umeng") in conv["reject"]
    assert ("ip", "1.2.3.4/32") in conv["reject"]
    assert ("wildcard", "adblock.*") in conv["direct"]
    assert len(bad) == 1  # PROXY policy is not representable in the filter file


def test_sgmodule_rewrite_conversion():
    ok, bad = convert.convert_sgmodule_rewrites([
        r"^https?:\/\/unet\.quark\.cn\/v3\/ad\/ - reject",
        r"^https?:\/\/a\.b\/x - reject-dict",
        r"^https?:\/\/a\.b\/y - reject-img",
        r"^https?:\/\/a\.b\/y - header",
    ], "test")
    assert ok[0]["regex"] == r"^https?://unet\.quark\.cn/v3/ad/"  # \/ unescaped for QX
    assert ok[0]["action"] == "reject"
    assert ok[1]["action"] == "reject-dict"
    assert ok[2]["action"] == "reject-img"
    assert len(bad) == 1


def test_parse_sgmodule_sections():
    text = "#!name=x\n[Rule]\nDOMAIN,a.com,REJECT\n\n# c\n[Script]\nfoo = bar\n[MITM]\nhostname = %APPEND% a.com\n"
    secs = convert.parse_sgmodule(text)
    assert secs["Rule"] == ["DOMAIN,a.com,REJECT"]
    assert secs["Script"] == ["foo = bar"]
    assert secs["MITM"] == ["hostname = %APPEND% a.com"]
    assert "URL Rewrite" not in secs
