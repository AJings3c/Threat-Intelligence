# Server Deployment Checklist

## 第一阶段：SQLite 单机部署

- [x] 使用 SQLite 持久化情报、去重 key、推送记录和采集器状态。
- [x] 启用 `PRAGMA journal_mode=WAL`，提高单机读写稳定性。
- [x] 启用 `PRAGMA busy_timeout=5000`，减少短时间并发写入失败。
- [x] 按 Telegram / 钉钉等通知渠道分别记录推送成功或失败。
- [x] 默认避免重复推送已经成功发过的情报。
- [ ] 把 `data/security_intel_hub.db` 放到服务器持久化目录。
- [ ] Docker 部署时挂载 volume，不要把数据库放在容器临时层。
- [ ] 配置定时任务，例如 cron、systemd timer 或容器内调度器。
- [ ] 配置数据库文件备份。
- [ ] 配置机器人 token、webhook、secret 等环境变量。

## 推荐服务器目录

```text
/opt/security-intel-hub/
  app/
  data/security_intel_hub.db
  logs/
```

## 推荐 cron

```cron
*/15 * * * * cd /opt/security-intel-hub/app && /usr/bin/python3 -m security_intel_hub --config config.prod.json --send >> /opt/security-intel-hub/logs/run.log 2>&1
```

## SQLite 适用条件

SQLite 适合：

- 单台服务器
- 一个定时任务或少量 worker
- 低频写入
- 主要用于去重、推送记录、状态保存

需要切 PostgreSQL 的信号：

- 多台服务器同时运行
- 多 worker 高频并发写入
- 增加 Web 后台和多人查询
- 需要复杂搜索、统计报表、权限隔离或高可用

## 本轮已改造

- 新增 `security_intel_hub/storage.py`
- CLI 新增 `--init-db`、`--show-stats`、`--no-storage`
- 配置新增 `storage.sqlite_path`
- 推送时按渠道过滤已成功推送的情报
- 推送成功/失败写入 `push_events`
- 情报正文和评分写入 `intel_items`
- 预留 `collector_state`，后续可以保存 X/Facebook/RSS 游标
