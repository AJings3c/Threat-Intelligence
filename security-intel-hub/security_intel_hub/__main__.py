from __future__ import annotations

import argparse
import sys
from pathlib import Path

from security_intel_hub.config import load_config
from security_intel_hub.http import HttpError
from security_intel_hub.pipeline import build_collectors, build_notifiers, collect_all, format_digest, rank_items
from security_intel_hub.storage import build_store


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect security intel and send hot digests.")
    parser.add_argument("--config", required=True, help="Path to config JSON.")
    parser.add_argument("--send", action="store_true", help="Send to enabled notifiers. Default only prints.")
    parser.add_argument("--init-db", action="store_true", help="Initialize SQLite storage and exit.")
    parser.add_argument("--show-stats", action="store_true", help="Print SQLite storage stats.")
    parser.add_argument("--no-storage", action="store_true", help="Disable SQLite storage for this run.")
    args = parser.parse_args()

    config_path = Path(args.config)
    config = load_config(config_path)
    _resolve_storage_path(config, config_path.parent)
    if args.no_storage:
        config["storage"] = {"enabled": False}

    store = build_store(config)
    if args.init_db:
        print("SQLite storage initialized." if store else "SQLite storage disabled.")
        return 0

    if args.show_stats and store:
        print(f"Storage stats: {store.stats()}")

    collectors = build_collectors(config)
    items, collection_errors = collect_all(collectors)
    ranked_items = rank_items(
        items,
        keywords=config.get("keywords", []),
        weights=config.get("weights", {}),
        max_items=config.get("max_items", 25),
    )

    new_count = 0
    if store:
        new_count = len(store.upsert_ranked_items(ranked_items))

    notifiers = build_notifiers(config) if args.send else []
    notifier_names = [notifier.name for notifier in notifiers]
    digest_items = (
        store.unpushed_for_any_notifier(ranked_items, notifier_names)
        if store and args.send
        else ranked_items
    )
    digest = format_digest(
        digest_items,
        empty_message="暂无新的待推送安全情报。" if args.send else "暂无命中安全情报。",
    )
    print(digest)
    if store:
        print(f"\nSQLite: new_items={new_count}, stats={store.stats()}")

    if collection_errors:
        print("\nCollection errors:", file=sys.stderr)
        for error in collection_errors:
            print(f"- {error}", file=sys.stderr)

    if args.send:
        notification_errors = _send_to_notifiers(notifiers, ranked_items, store)
        if notification_errors:
            print("\nNotification errors:", file=sys.stderr)
            for error in notification_errors:
                print(f"- {error}", file=sys.stderr)
            return 2

    return 1 if collection_errors else 0


def _send_to_notifiers(notifiers, ranked_items, store) -> list[str]:
    if not notifiers:
        return ["no enabled notifiers"]

    errors: list[str] = []
    for notifier in notifiers:
        channel_items = (
            store.unpushed_for_notifier(ranked_items, notifier.name)
            if store
            else ranked_items
        )
        if not channel_items:
            continue

        digest = format_digest(channel_items, empty_message="暂无新的待推送安全情报。")
        try:
            notifier.notify("安全情报热点摘要", digest)
            if store:
                store.record_push_events(channel_items, notifier=notifier.name, status="success")
        except HttpError as exc:
            error = f"{notifier.name}: {exc}; body={exc.body[:300]}"
            errors.append(error)
            if store:
                store.record_push_events(channel_items, notifier=notifier.name, status="failed", error=error)
        except Exception as exc:  # noqa: BLE001 - one channel should not block the rest.
            error = f"{notifier.name}: {type(exc).__name__}: {exc}"
            errors.append(error)
            if store:
                store.record_push_events(channel_items, notifier=notifier.name, status="failed", error=error)
    return errors


def _resolve_storage_path(config: dict[str, object], config_dir: Path) -> None:
    storage = config.get("storage")
    if not isinstance(storage, dict):
        return
    sqlite_path = storage.get("sqlite_path")
    if not isinstance(sqlite_path, str) or not sqlite_path:
        return
    path = Path(sqlite_path)
    if not path.is_absolute():
        storage["sqlite_path"] = str(config_dir / path)


if __name__ == "__main__":
    raise SystemExit(main())
