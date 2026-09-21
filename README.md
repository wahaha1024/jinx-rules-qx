# jinx-rules-qx

将 [VME98/jinx-rules](https://github.com/VME98/jinx-rules)（Jinx DNS 去广告规则）自动转换为单个 Quantumult X 分流规则文件。

- 每天北京时间 9:00 由 GitHub Actions 自动拉取上游并重新生成
- 白名单域名 → `DIRECT`（放行在前，防止误杀）
- 黑名单域名 / 广告 URL → `REJECT`

## 订阅地址

```
https://raw.githubusercontent.com/wahaha1024/jinx-rules-qx/main/jinx-adblock-qx.list
```

在 Quantumult X → 分流 → 引用（`[filter_remote]`）中添加即可，规则文件内自带 DIRECT/REJECT 指向，无需再选政策。

中国大陆网络直连 raw.githubusercontent.com 可能不通，可改用 jsDelivr CDN：

```
https://cdn.jsdelivr.net/gh/wahaha1024/jinx-rules-qx@main/jinx-adblock-qx.list
```

## 手动触发同步

GitHub 仓库 → Actions → "Sync upstream and rebuild QX rules" → Run workflow。
