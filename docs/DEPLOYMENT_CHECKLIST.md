# Deployment Checklist

## First Server Version

- Use a single backend process or one scheduled worker.
- Set `DATA_DIR` to a persistent local disk path, for example `/var/lib/threat-intel`.
- Do not place the SQLite database on NFS or a temporary directory.
- Back up `DATA_DIR/threat-intel.db` regularly.
- Configure `REFRESH_INTERVAL_MS` conservatively to avoid upstream rate limits.
- Set `API_TOKEN` for private API/SIEM access.
- Set `NOTIFY_TEST_TOKEN` before exposing `POST /api/notify/test` in production.

## Social Source Credentials

- X: provide `X_BEARER_TOKEN`; optionally tune `X_QUERY` and `X_MAX_RESULTS`.
- Facebook: provide `FACEBOOK_ACCESS_TOKEN` and comma-separated `FACEBOOK_PAGE_IDS`.
- Keep API tokens in environment variables or secret management, not in Git.
- Use only official X/Facebook APIs and account permissions.

## Notification Channels

- Set `NOTIFY_ENABLED=true`.
- Configure at least one of `DINGTALK_WEBHOOK`, `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`,
  `SLACK_WEBHOOK`, or `WEBHOOK_URL`.
- Use `NOTIFY_MIN_SEVERITY` and `NOTIFY_SOURCES` to control noise.
- Enable `DATA_DIR` so `push_events` records per-channel success/failure and avoids repeat pushes.

## When To Move From SQLite To PostgreSQL

SQLite is suitable for a single server with light write traffic. Move to PostgreSQL when you need:

- multiple backend instances writing at the same time;
- a multi-user admin UI with frequent writes;
- complex search and reporting over a large indicator history;
- remote database access, high availability, or role-based database permissions.
