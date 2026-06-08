# Security Intel Hub

这个目录是一个最小可运行骨架，用来把 X、Facebook Page/RSS 等来源的安全情报归一化、去重、打分，并发送到 Telegram 或钉钉机器人。

当前会话的工作区没有已有项目源码，所以这里先提供独立版本，后续可以迁到真实项目里。

## 能力

- 采集器插件：`XRecentSearchCollector`、`FacebookPageCollector`、`RssCollector`
- 通知器插件：`TelegramNotifier`、`DingTalkNotifier`
- 管道能力：关键词命中、基础热度评分、URL 去重、摘要格式化
- SQLite 持久化：情报入库、跨运行去重、推送成功/失败记录、采集器状态表
- 安全边界：只使用官方 API 或公开 RSS；不做登录态模拟、不抓取私密内容、不绕过平台限制

## 快速运行

```bash
cd /Users/ki10moc/Documents/Codex/2026-06-08/1-2-telegrame-3-facebook-x/outputs/security-intel-hub
python3 -m unittest discover -s tests -v
python3 -m security_intel_hub --config config.example.json --init-db
python3 -m security_intel_hub --config config.example.json
```

默认只启用 CISA RSS，不会向机器人发送消息。启用发送时：

```bash
export TELEGRAM_BOT_TOKEN="..."
export TELEGRAM_CHAT_ID="..."
export DINGTALK_WEBHOOK="..."
export DINGTALK_SECRET="..."
python3 -m security_intel_hub --config config.example.json --send
```

查看数据库统计：

```bash
python3 -m security_intel_hub --config config.example.json --show-stats
```

`--send` 会按通知渠道分别过滤已经成功推送过的情报，避免重复刷屏。数据库默认路径是配置文件所在目录下的 `data/security_intel_hub.db`。

## 服务器部署

SQLite 适合单台服务器、低频定时采集和机器人推送。部署时建议：

- 把 `data/security_intel_hub.db` 放在持久化目录
- Docker 部署时挂载 volume
- 不要把 SQLite 放在 NFS/网络盘
- 定期备份 `.db` 文件
- 使用 cron 或 systemd timer 定时执行 `python3 -m security_intel_hub --config config.prod.json --send`

详细清单见 `DEPLOYMENT_CHECKLIST.md`。

## X 配置

启用 `collectors.x.enabled` 后，设置 `X_BEARER_TOKEN`。默认接口是 X API v2 recent search：

```json
{
  "enabled": true,
  "bearer_token": "${X_BEARER_TOKEN}",
  "query": "(CVE OR 0day OR exploit OR RCE OR ransomware OR APT OR IoC OR breach) lang:en -is:retweet"
}
```

## Facebook 配置

启用 `collectors.facebook.enabled` 后，设置 `META_ACCESS_TOKEN` 和要关注的 `page_ids`。该采集器走 Meta Graph API 的 Page posts/feed 类接口，实际可读范围取决于账号、App、Page 权限与 App Review。

```json
{
  "enabled": true,
  "access_token": "${META_ACCESS_TOKEN}",
  "page_ids": ["example_page_id"],
  "graph_version": "v23.0"
}
```

## 扩展方式

新增来源时实现一个 `collect()` 方法，返回 `list[IntelItem]`，再在 `pipeline.build_collectors()` 注册。新增通知渠道时实现 `notify(title, text)`，再在 `pipeline.build_notifiers()` 注册。

推荐后续升级：

- 把配置改为数据库或后台管理页面
- 接入持久化去重，避免每天重复推送同一条消息
- 增加来源可信度、转发数、CVE 严重度、CISA KEV 命中等评分维度
- 使用队列和定时任务，让采集、聚合、推送解耦
- 对 X/Facebook 增加速率限制和失败重试策略

## 官方文档

- X recent search: https://docs.x.com/x-api/posts/search/quickstart/recent-search
- Telegram Bot API `sendMessage`: https://core.telegram.org/bots/api#sendmessage
- 钉钉自定义机器人: https://open.dingtalk.com/document/orgapp/custom-robot-access
- Meta Graph API: https://developers.facebook.com/docs/graph-api/
