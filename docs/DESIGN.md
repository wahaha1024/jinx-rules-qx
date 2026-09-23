# jinx-rules-qx 设计文档

把 Jinx（iOS DNS 过滤 App）的规则自动转换成 Quantumult X 可订阅的规则文件，每 6 小时自动更新一次。

---

## 一、整体架构

```
┌─────────────────────────────────────────────────────────────┐
│  外部数据源（每次运行都重新拉取）                              │
│                                                             │
│  ① VME98/jinx-rules（GitHub，master 分支）                    │
│     12 个规则文件：域名黑白名单 + URL 黑白名单 + MITM 跳过清单   │
│                                                             │
│  ② uxudjs/Shadowrocket 的 fuck_apps_ad_sr.sgmodule            │
│     [Rule] 35 条 + [URL Rewrite] 107 条（其余段 QX 无法转换）    │
│                                                             │
│  ③ config/manual_extras.list（本仓库手工维护，兜底补充）        │
└───────────────────────────┬─────────────────────────────────┘
                            │  urllib 下载（3 次重试）
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  converter/convert.py（唯一转换核心，纯标准库）                 │
│                                                             │
│  解析 → 分类 → 白名单排除 → 去重 → 排序 → 自校验 → 写文件        │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  产物                                                       │
│                                                             │
│  jinx-adblock-qx.list            ← 主订阅文件（QX 分流用）      │
│  generated/jinx-qx-rewrite.conf  ← 可选：URL 重写（QX 重写用）  │
│  generated/jinx-mitm-required.txt ← 可选：解密所需域名          │
│  generated/jinx-mitm-skip.txt     ← 可选：必须排除解密的域名     │
│  generated/qx-config-snippet.conf ← 可选：可直接粘贴的配置片段   │
│  generated/unsupported.log        ← 审计：跳过了什么、为什么     │
└───────────────────────────┬─────────────────────────────────┘
                            │  GitHub Actions 每 6 小时
                            ▼
                  github-actions[bot] 提交（有变化才提交）
                            │
                            ▼
        raw.githubusercontent.com/wahaha1024/jinx-rules-qx/main/...
                            │
                            ▼
                     用户的 Quantumult X
```

**设计原则**：上游规则改一行，用户 QX 里的订阅自动跟上，中间不需要任何人手工干预；转换器拿不准的规则一律不输出，并留下审计记录。

---

## 二、数据流：一次转换的完整过程

### 第 1 步：加载配置与源文件

`config/sources.json` 是唯一配置入口：

```json
{
  "repository": "VME98/jinx-rules",     // 主上游
  "branch": "master",
  "safe_mode": true,                    // 安全模式总开关
  "convert_generic_path": false,        // 无 host 的泛路径：不转换
  "convert_unknown_url": false,         // 无法识别的 URL：不转换
  "convert_regex": false,               // 含正则元字符的 URL：不转换
  "deduplicate": true,                  // 去重
  "single_filter_output": "jinx-adblock-qx.list",
  "mitm_fold_suffixes": [],             // 可选：把同后缀域名折叠成 *.suffix
  "sources": { ... },                   // 12 个上游文件的路径清单
  "extra_sources": [ ... ]              // 额外数据源（sgmodule / 手工清单）
}
```

运行方式有两种：

| 方式 | 命令 | 用途 |
|---|---|---|
| 联网 | `python converter/convert.py` | CI 与日常使用 |
| 本地 | `python converter/convert.py --source-dir /path/to/repo` | 调试（可 `--commit` 指定版本头）|

下载阶段每个文件失败重试 3 次（间隔 2/4/6 秒）；额外数据源（sgmodule）失败时回退到 `tools/` 下的本地缓存，全都没有则跳过并记警告——**单个源挂掉不影响整体产出**。

### 第 2 步：解析域名规则

每个文件逐行读取，先做基础清洗：去首尾空白、丢掉空行、丢掉 `#` 和 `;` 开头的注释行。**注意：清洗阶段不做大小写转换**——URL 的 path 是大小写敏感的，`getAdverList` 小写化之后就永远匹配不上了。域名文件在各自的解析器里再单独小写。

分类器 `classify_domain()` 把一行归入七类之一：

| 输入形态 | 分类 | 处理方式 |
|---|---|---|
| `ads.example.com` | `exact` | → `host, ads.example.com, reject` |
| `*.example.com` | `suffix` | → `host-suffix, example.com, reject` |
| `p*-ad.adkwai.com`（中间带星） | `wildcard` | → `host-wildcard, p*-ad.adkwai.com, reject` |
| `https://a.b/c/d` | `url` | 转入 URL 流水线（第 4 步） |
| `/splash` | `path` | 转入 URL 流水线 |
| `1.2.3.4` 或 `10.0.0.0/8` | `ip` | → `ip-cidr, ..., reject` |
| `wpad`（单标签）、`zalo-ads-480-td.`（尾点） | `skip` | 丢弃并记入 `unsupported.log` |

判定顺序很关键：先查是不是 URL（`http://` 前缀），再查 path（`/` 开头），再查 IP，最后才当域名处理。否则 `1.2.3.4` 会被当成合法域名。

**为什么 `wpad` 被判 skip**：域名校验要求至少含一个点，裸单词不是合法域名。这类被跳过的清单最下方会出现在 `unsupported.log`，需要时可以手工补进 `config/manual_extras.list`。

### 第 3 步：合并额外数据源

两个来源合并进**同一套桶**（`wl` 白名单桶 / `bl` 黑名单桶，各含 exact/suffix/wildcard/keyword/ip 五个集合），合并即去重：

**sgmodule（Shadowrocket/Surge 模块）**：

- `[Rule]` 段：支持 `DOMAIN` / `DOMAIN-SUFFIX` / `DOMAIN-WILDCARD` / `DOMAIN-KEYWORD` / `IP-CIDR`，`REJECT` 进黑名单桶，`DIRECT` 进白名单桶。其他类型（`AND` 原子规则、`PROCESS-NAME` 等）记入审计日志。
- `[URL Rewrite]` 段：`pattern - action` 形式。动作 `reject` / `reject-200` / `reject-img` / `reject-dict` / `reject-array` 原样保留（QX 都支持），其余（`header`、`302` 等）记入审计。
- `[Body Rewrite]` / `[Script]` / `[MITM]`：**明确不转换**。前两者是 Surge 的 jq 响应改写与远程脚本能力，QX 没有等价物；MITM 主机名列表永远手工维护。它们的条数会写进审计日志，让用户知道"这些效果要回 Surge 里开"。

**手工清单（`config/manual_extras.list`）**：QX 语法直接写，用于补上游和 sgmodule 都没有的规则：

```
host, wpad, reject
host, sdkquic.e.qq.com, reject
^https?://example\.com/ad url reject-dict
```

### 第 4 步：URL 规则流水线（最复杂的一步）

URL 规则不能直接塞进 QX 分流文件——QX 的 `[filter_local]`/`[filter_remote]` 只认 host / host-suffix / host-wildcard / host-keyword / ip-cidr，没有 URL 维度。所以 URL 规则走**重写文件**（`[rewrite_local]` / `[rewrite_remote]`）。

每条 URL 规则依次经过这些关卡，**任何一关过不了就跳过并记审计**：

```
原始行
  │
  ├─ ① 解析出 host + path
  │     ● https://a.b/c  → (a.b, /c)
  │     ● /splash        → ("", /splash)  ← 无 host 的泛路径
  │     ● .splash        → 解析失败（点前缀子串，语义无法还原）
  │
  ├─ ② host 在域名白名单里？           → 跳过（白名单优先，共排除了 28 条）
  │
  ├─ ③ path 命中 URL 白名单？          → 跳过（B 站弹幕、支付接口等）
  │
  ├─ ④ host 已被域名黑名单覆盖？        → 跳过（死规则，共 107 条）
  │     例：ad.maoyan.com 被通配规则 ad.* 整体拦截，重写多余
  │
  ├─ ⑤ host 为空（泛路径）？
  │     ├ safe_mode 打开 → 跳过（共 136 条）
  │     └ convert_generic_path=true → 生成 ^https?://[^/]*/splash(?:\?|$)
  │
  ├─ ⑥ path/host 含正则元字符 ()[]{}+^$|\ ？
  │     ├ convert_regex=false → 跳过
  │     └ =true → 按原样当作正则使用
  │
  ├─ ⑦ path 为空或 "/"？               → 降级成 host 规则，进分流文件（共 1 条）
  │
  └─ ⑧ 生成 QX 重写规则
        ^https?://<转义 host>(?::\d+)?<转义 path>(?:\?|$) url reject-200
```

**正则生成的细节**：

- host 部分：`.` → `\.`，`-` 保持（QX 里不必转义），中间通配 `*` → `[^/]*`
- path 部分：`.` → `\.`，`*` → `.*`（路径通配要跨层级）
- **端口容错**：host 后插入 `(?::\d+)?`，让 `host:8443/xxx` 也能命中。这是对比 AdRules 模块后发现我们缺失的能力。
- 结尾 `(?:\?|$)`（除非 path 本身以 `*` 结尾）：要求路径到此为止或者是查询串开头，避免 `/ad` 误伤 `/advertisement`

**为什么 `ad` 类规则要小心**：上游有 46 条 host 带通配的 URL（如 `https://img*.360buyimg.com/jddjadvertise`），以及 2 条空路径 URL（`^https?://[^/]+$` 可降级）。泛路径（`/splash`、`/api/ad`）误杀面太大——任何 App 的启动页都可能叫 `/splash`，所以在安全模式下默认不转。

### 第 5 步：白名单优先（QX 规则顺序敏感）

QX 分流自上而下匹配，先命中先生效。所以：

1. **输出顺序**：白名单规则全部排在前面，黑名单规则全部排在后面。
2. **转换阶段排除**：黑名单域名如果命中白名单（exact 相等 / suffix 后缀 / wildcard 通配 / keyword 包含），直接从黑名单桶里删掉——它永远不会生效，留着只是噪音。
3. **审计**：`host-keyword` 规则如果也命中白名单域名，写入 `unsupported.log` 报警（当前 0 条冲突）。

这也是为什么 README 里反复强调：**订阅本文件时不要设 `force-policy=reject`**——那会让文件内的 direct 白名单规则全部失效。

### 第 6 步：去重与排序

- 去重粒度：域名按 `(类型, 值)` 去重；重写规则按生成后的正则字符串去重。上游同时维护"合并版 + 拆分版"文件，重叠很多（实测去掉 4210 条域名行、762 条重复重写）。
- 排序：白名单在前 → 每种类型内按字典序（exact → suffix → wildcard → keyword → ip-cidr）。**排序让 git diff 稳定**，否则集合迭代顺序变化会导致每次 CI 都产生无意义的提交。

### 第 7 步：写文件

**主订阅文件 `jinx-adblock-qx.list`**（QX 分流）：

```
# Generated by jinx-rules-qx converter. DO NOT EDIT BY HAND.
# Source: https://github.com/VME98/jinx-rules
# Merged source: fuck_apps_ad_sr (https://raw.githubusercontent.com/...)
# Upstream commit: 3fd15f94fedc
# Whitelist (direct) rules come first on purpose; QX matches top-down.
# Generated: 2026-09-21T07:06:39Z
# ==== WHITELIST (direct) ====
host, 95516.com, direct
...
# ==== BLACKLIST (reject) ====
host, 1500020991.vodplayer.wxamedia.com, reject
...
```

**重写文件 `generated/jinx-qx-rewrite.conf`**（QX 重写）：

```
[rewrite_local]
^https?://dongchedi\.com(?::\d+)?/motor/ad(?:\?|$) url reject-200
^https?://res\.xiaojukeji\.com/resapi/activity/getMulti\? url reject-dict
```

**MITM 相关两个文件**：

- `jinx-mitm-required.txt` + `.oneline.txt`：重写要生效、必须被解密的 host（330 条），已排除 `jinx-mitm-skip.txt` 里的域名。默认输出精确域名（不擅自放宽解密范围），`mitm_fold_suffixes` 可选开启后缀折叠。
- `jinx-mitm-skip.txt`：33 个**绝不能解密**的域名（支付、系统验证、iCloud、推送通道等）。

**配置片段 `generated/qx-config-snippet.conf`**：可直接粘贴进 QX 配置的 `[filter_remote]` / `[rewrite_remote]` / `[mitm]` 三段，含告诫注释。

**审计文件 `unsupported.log`**：每行 `原因 :: 来源文件`，覆盖所有跳过项。

### 第 8 步：自校验（防止把坏文件推给用户）

写完之后立刻读回产物做校验，**任何一条不过就非零退出，CI 直接失败、不提交**：

| 校验项 | 意义 |
|---|---|
| 每行匹配 `^(host\|host-suffix\|...), 值, (direct\|reject)$` | 语法错误立刻暴露 |
| direct 规则不得出现在 reject 规则之后 | 白名单优先的排序保证 |
| 无重复行 | 去重失效会立刻暴露 |
| 每条重写正则 `re.compile()` 能编译 | 正则拼接错误立刻暴露 |
| 四个产出文件都非空 | 上游改目录结构等灾难性变化会立刻暴露 |

之前 `daijia.kuaidadi.com:443` 这种带端口的非法 host 混进 MITM 清单，就是靠这层校验思路发现并修掉的。

---

## 三、安全模式：为什么"宁可少拦不可误杀"

`safe_mode: true` 时，下面这些**一律不转**：

| 类别 | 例子 | 理由 |
|---|---|---|
| 无 host 泛路径 | `/splash`、`/app_ads` | 所有 App 的启动页都可能叫这个名，误杀整个 App |
| 通用路径白名单 | `/api/pay/`、`/api/login/` | 语义是"所有站点的支付接口"，不转才安全 |
| 正则形 URL | 含 `()` `[]` 的规则 | 直接当 QX 正则用风险不可控 |
| 点前缀子串 | `.ads.`、`.ad.` | 原始语义是"路径含该子串"，无法可靠还原 |
| 单标签域名 | `wpad` | 不是合法域名 |
| 死规则 | host 已被域名层拦截 | 冗余，白白增加规则数 |

代价是漏掉一部分广告；收益是**不会因为一条规则把用户某个 App 的主要功能打死**。被跳过的东西全部可以在 `unsupported.log` 里看到，用户想激进可以自己改配置开关。

---

## 四、CI 流水线

`.github/workflows/update.yml`：

```
触发条件：cron 每 6 小时（0 */6 * * *） / 手动 dispatch / push 改动 converter|config|workflow
                    │
                    ▼
  ① actions/checkout          拉代码
  ② actions/setup-python      装 Python 3.11
  ③ python converter/convert.py   联网转换 + 自校验（校验失败 CI 红）
  ④ python -m pytest tests/ -q    35 个单元测试
  ⑤ git add jinx-adblock-qx.list generated/
     git diff --cached --quiet ?  → 无变化：打印 "No rule changes." 退出
                    │ 有变化
                    ▼
     git commit（github-actions[bot] 身份）
     for i in 1 2 3: git pull --rebase && git push && break
     （push 竞态由 rebase 重试解决）
                    │
                    ▼
  ⑥ 打印 "发现 N 条无法安全转换的规则" + unsupported.log 前 20 行
```

要点：

- **有变化才提交**：上游没更新时不会产生空提交，git 历史干净。
- **`permissions: contents: write`**：机器人需要写权限。
- **`concurrency: update-rules`**：同一时间只跑一个，避免两个 run 互相踩。
- **push 失败重试**：并发触发时 `git pull --rebase` 后重推，最多 3 次退避（15/30/45 秒）。

---

## 五、与 AdRules 模块的对比结论

`tools/compare_adrules.py` 可复现的实测结果（对比 `adrules.bittersweetx.dpdns.org/modules/shared_log_jinx.sgmodule`）：

| 维度 | AdRules（Surge 版） | 本仓库 | 结论 |
|---|---|---|---|
| 域名拦截 | 3686 | 4225 | 本仓库多 168 条（含 sgmodule 合并的 50 条与通配） |
| URL 重写 | 374 | 853 | 其中 315 条双方重叠 |
| 需解密域名 | 360（手工） | 330（自动生成） | 311 条完全一致 |
| UDP/QUIC 精准拦截 | 8 条 `AND` 规则 | 移植：2 条整体拒绝 + 3 条 GDT/Pangle 端点重写 | QX 无 `AND` 语法；SDK 域名整体拒绝，端点用 rewrite 补刀，剩余由全局 `udp_drop_list = QUIC` 覆盖 |
| 白名单豁免 | `AND(...NOT...)` 原子规则 | 转换阶段排除 | 效果等价，且不占运行时规则 |
| GDT/Pangle SDK 放行 | 9 域名 DIRECT + 端点拦截 | 已移植（`manual_extras.list` 精准处理层） | 等价：连接层 direct，广告端点 rewrite 拦截 |

AdRules 独有而我们已补齐的：端口容错 `(?::\d+)?`、`wpad`、`sdkquic.e.qq.com`、GDT/Pangle SDK 放行与端点重写。

---

## 六、已知限制

1. **QX 无 QUIC/UDP 精细拦截**：Surge 的 `AND,((NETWORK,UDP),(DEST-PORT,443),(DOMAIN,...))` 在 QX 没有对应语法。替代方案是在 `[general]` 配 `udp_drop_list = QUIC`（会强制 App 回落 TCP，代价是首连略慢）。
2. **Surge 专属能力无法搬运**：sgmodule 的 `[Script]`（101 条脚本）、`[Body Rewrite]`（45 条 jq 改写）在 QX 没有等价物。需要用这些效果就继续在 Surge/Shadowrocket 里启用该模块，两边互不冲突。
3. **HTTPS 重写依赖 MITM**：不解密的域名，重写规则不会触发。`jinx-mitm-required.txt` 就是为此准备的清单。
4. **上游结构变化会中断**：若上游改了目录结构或文件名，转换器会因文件缺失而产出空文件，自校验会拦住并在 CI 报错（而非静默推空文件）。
5. **本机 git 直连 GitHub 不稳**：此仓库配置了走本地 Clash 代理（`http.https://github.com.proxy`），仅影响本机；CI 在 ubuntu 上跑不受影响。

---

## 七、目录结构

```
jinx-rules-qx/
├── jinx-adblock-qx.list           ← 主订阅文件（QX 只订阅这一个即可）
├── .github/workflows/update.yml   ← CI：每 6 小时转换 + 测试 + 提交
├── config/
│   ├── sources.json               ← 唯一配置：上游清单 + 安全开关
│   └── manual_extras.list         ← 手工补充规则（QX 语法）
├── converter/convert.py           ← 转换核心（纯标准库，约 900 行）
├── generated/                     ← 可选产物（重写 / MITM / 配置片段 / 审计）
├── tests/test_converter.py        ← 35 个单元测试
├── tools/
│   ├── compare_sources.py         ← 与 Shadowrocket sgmodule 的重复度对比
│   └── compare_adrules.py         ← 与 AdRules 模块的差异对比
└── README.md                      ← 面向使用者的说明
```

---

## 八、常用操作

```bash
# 联网转换（CI 用的就是这条）
python converter/convert.py

# 用本地 checkout 调试
python converter/convert.py --source-dir /path/to/jinx-rules --commit abc1234

# 跑测试
python -m pip install pytest && python -m pytest tests/ -q

# 看与 AdRules / sgmodule 的差异（结果可复现）
python tools/compare_adrules.py
python tools/compare_sources.py
```

**想调整行为时改哪里**：

| 想做的事 | 改哪里 |
|---|---|
| 加一个新上游文件 | `config/sources.json` 的 `sources` |
| 加一个 sgmodule 源 | `config/sources.json` 的 `extra_sources`（`type: sgmodule`）|
| 补一条上游没有的规则 | `config/manual_extras.list` |
| 让泛路径也转换（激进） | `config/sources.json` 把 `safe_mode` 设 false 或 `convert_generic_path` 设 true |
| 缩短 MITM 清单 | `config/sources.json` 的 `mitm_fold_suffixes` 填后缀（如 `"qishui.com"`）|
| 换更新频率 | `.github/workflows/update.yml` 的 `cron` |
