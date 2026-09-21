# jinx-rules-qx

把 [VME98/jinx-rules](https://github.com/VME98/jinx-rules)（Jinx iOS DNS 过滤 App 的规则仓库）自动转换成 **Quantumult X** 可订阅的分流 / 重写规则文件。

- GitHub Actions 每 **6 小时**拉取上游规则并转换一次，有变化才提交。
- 转换器采用**安全模式**：宁可少拦、不可误杀。无法安全转换的规则写入 `generated/unsupported.log` 并在 Actions 日志中提示数量。
- QX 只需订阅本仓库 `raw.githubusercontent.com` 直链，不接触上游仓库。

## 订阅文件

| 文件 | 用途 | 内容 |
|---|---|---|
| [`generated/jinx-qx-filter.list`](generated/jinx-qx-filter.list) | `[filter_remote]` 域名分流 | 白名单（direct）在前，黑名单（reject）在后 |
| [`generated/jinx-qx-rewrite.conf`](generated/jinx-qx-rewrite.conf) | `[rewrite_remote]` URL 广告拦截 | `url reject-200` 正则规则 |
| [`generated/jinx-mitm-skip.txt`](generated/jinx-mitm-skip.txt) | MITM 排除参考 | 不应对其解密（跳过 MITM）的域名 |
| [`generated/unsupported.log`](generated/unsupported.log) | 转换审计 | 被跳过的规则及原因 |

生成文件头部带上游 commit 与生成时间，可直接溯源。

## QX 推荐配置

在 QX 配置文件的 `[filter_remote]` 段加入（**不要**写 `force-policy=reject`——本文件自带白名单 direct 规则，写了会导致白名单失效）：

```ini
[filter_remote]
https://raw.githubusercontent.com/wahaha1024/jinx-rules-qx/main/generated/jinx-qx-filter.list, tag=Jinx-Domain, update-interval=21600, enabled=true

[rewrite_remote]
https://raw.githubusercontent.com/wahaha1024/jinx-rules-qx/main/generated/jinx-qx-rewrite.conf, tag=Jinx-URL, update-interval=21600, enabled=true
```

### MITM

`rewrite.conf` 中的 HTTPS 拦截需要 QX 开启 MITM。操作方式：

1. 查看 [`generated/jinx-mitm-skip.txt`](generated/jinx-mitm-skip.txt)，把这些域名从你的 `[mitm] hostname` 中**排除**（这些域名（如 `*.apple.com`、`*.icloud.com`）被上游标记为不应解密）。
2. MITM 配置始终手工维护，本仓库不会、也不应自动改写你的 `[mitm]` 段。

### 与其他规则叠加的顺序建议

QX 分流自上而下匹配。若同时使用 AdRules 等广告规则与本文件：

```ini
[filter_remote]
; 1. 其他去广告规则（如有）
; 2. 本文件（自带白名单，务必排在其引用的黑名单类规则之后……实际放在你要比较的规则之间即可）
; 3. 规则修正 / 去广告修正规则（放最后，兜底放行被误杀的域名）
```

原则：**修正规则（direct 放行）永远排在最后**，才能覆盖前面规则的拦截。

## 转换规则

上游 → QX 映射（详见 `converter/convert.py`）：

| 上游写法 | QX 规则 |
|---|---|
| `ads.example.com` | `host, ads.example.com, reject` |
| `*.example.com` | `host-suffix, example.com, reject` |
| `p*-ad.adkwai.com`（中间通配） | `host-wildcard, p*-ad.adkwai.com, reject` |
| `https://a.b/c/d`（完整 URL） | `^https?://a\.b/c/d(?:\?|$) url reject-200` |
| URL 白名单 | 转换阶段直接从黑名单中排除 |
| 通用路径（`/api/pay/` 等，无 host） | **跳过**（safe_mode，误杀面太大） |
| 泛路径（`/splash`、`/api/ad` 等） | **跳过**（safe_mode） |
| 空路径 URL | 降级为 host 规则 |
| 正则形 URL | **跳过**（`convert_regex: false`） |

白名单永远排在黑名单前面输出——QX 规则顺序敏感，先匹配先生效。

## 本地开发

```bash
# 从上游下载并转换
python converter/convert.py

# 用本地 checkout 转换（调试用）
python converter/convert.py --source-dir /path/to/jinx-rules

# 测试
python -m pip install pytest
python -m pytest tests/ -q
```

配置在 `config/sources.json`：上游仓库、分支、源文件清单与安全开关（`safe_mode` / `convert_generic_path` / `convert_unknown_url` / `convert_regex` / `deduplicate`）。

## 致谢与声明

- 规则内容全部来自 [VME98/jinx-rules](https://github.com/VME98/jinx-rules)，本仓库只做格式转换。
- 转换器在安全模式下只输出"确定安全"的规则；被跳过的规则都记录在 `unsupported.log` 中，可自行评估后补充。
