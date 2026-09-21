# jinx-rules-qx

把 [VME98/jinx-rules](https://github.com/VME98/jinx-rules)（Jinx iOS DNS 过滤 App 的规则仓库）自动转换成 **Quantumult X** 可订阅的分流规则文件。

- GitHub Actions 每 **6 小时**拉取上游规则并转换一次，有变化才提交。
- 转换器采用**安全模式**：宁可少拦、不可误杀。无法安全转换的规则写入 `generated/unsupported.log` 并在 Actions 日志中提示数量。
- **单文件交付**：QX 只需订阅一个文件。

## 订阅地址

```
https://raw.githubusercontent.com/wahaha1024/jinx-rules-qx/main/jinx-adblock-qx.list
```

在 Quantumult X → 分流 → 引用（`[filter_remote]`）中添加即可。文件内白名单（direct）在前、黑名单（reject）在后，**不要**对该远程资源设置 `force-policy=reject`——那会让白名单失效。

中国大陆网络直连 raw.githubusercontent.com 可能不通，可改用 jsDelivr CDN：

```
https://cdn.jsdelivr.net/gh/wahaha1024/jinx-rules-qx@main/jinx-adblock-qx.list
```

## 可选：URL 重写文件

上游还有约 750 条完整 URL 广告规则（如 `https://xxx/api/getAdverList`），这类规则无法放进分流文件（QX 分流只认域名/IP），已转成 QX 重写规则单独发布：

```
https://raw.githubusercontent.com/wahaha1024/jinx-rules-qx/main/generated/jinx-qx-rewrite.conf
```

在 QX → 重写 → 引用（`[rewrite_remote]`）中添加。HTTPS 重写需要开启 MITM；参考 [`generated/jinx-mitm-skip.txt`](generated/jinx-mitm-skip.txt) 把不应解密的域名（`*.apple.com` 等）从你的 `[mitm] hostname` 中排除。MITM 配置始终手工维护，本仓库不会自动改写你的 `[mitm]` 段。

## 文件清单

| 文件 | 用途 |
|---|---|
| `jinx-adblock-qx.list` | **主订阅文件**：域名分流（白名单 direct → 黑名单 reject） |
| `generated/jinx-qx-rewrite.conf` | 可选：URL 正则重写（`url reject-200`） |
| `generated/jinx-mitm-skip.txt` | 可选：MITM 排除域名参考 |
| `generated/unsupported.log` | 转换审计：被跳过的规则及原因 |

生成文件头部带上游 commit 与生成时间，可直接溯源。

## 与其他规则叠加的顺序建议

QX 分流自上而下匹配。若同时使用 AdRules 等广告规则与本文件：

```ini
[filter_remote]
; 1. 其他去广告规则（如有）
; 2. 本文件
; 3. 规则修正 / 去广告修正规则（放最后）
```

原则：**修正规则（direct 放行）永远排在最后**，才能覆盖前面规则的拦截。

## 转换规则

上游 → QX 映射（详见 `converter/convert.py`）：

| 上游写法 | QX 规则 |
|---|---|
| `ads.example.com` | `host, ads.example.com, reject` |
| `*.example.com` | `host-suffix, example.com, reject` |
| `p*-ad.adkwai.com`（中间通配） | `host-wildcard, p*-ad.adkwai.com, reject` |
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
