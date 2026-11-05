# language: Python 3.11+, file: cf/store.py
# *sqlite persistence — campaigns, targets, events, beacons, hits*
from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Self

from .util import new_token

SCHEMA = """
CREATE TABLE IF NOT EXISTS campaigns (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    scenario    TEXT NOT NULL DEFAULT 'browser_update',
    base_url    TEXT NOT NULL DEFAULT '',
    created_at  REAL NOT NULL,
    meta        TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_campaigns_name ON campaigns(name);
CREATE TABLE IF NOT EXISTS targets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id  TEXT NOT NULL,
    token        TEXT NOT NULL UNIQUE,
    label        TEXT NOT NULL DEFAULT '',
    email        TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'created',
    created_at   REAL NOT NULL,
    meta         TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_targets_campaign ON targets(campaign_id);
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id  TEXT NOT NULL,
    beacon_id    TEXT NOT NULL DEFAULT '',
    kind         TEXT NOT NULL,
    payload      TEXT NOT NULL DEFAULT '',
    created_at   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_campaign ON events(campaign_id, id);
CREATE TABLE IF NOT EXISTS beacons (
    beacon_id    TEXT PRIMARY KEY,
    campaign_id  TEXT NOT NULL,
    state        TEXT NOT NULL DEFAULT 'created',
    updated_at   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS send_profiles (
    name     TEXT PRIMARY KEY,
    config   TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS webhooks (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    url   TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS hits (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    token        TEXT NOT NULL,
    kind         TEXT NOT NULL,
    ip           TEXT NOT NULL DEFAULT '',
    ua           TEXT NOT NULL DEFAULT '',
    referer      TEXT NOT NULL DEFAULT '',
    extra        TEXT NOT NULL DEFAULT '{}',
    created_at   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hits_token ON hits(token);
"""

VALID_STATUSES = (
    "created",
    "lured",
    "delivered",
    "clicked",
    "executed",
    "dead",
)


class Store:
    """One writer, WAL mode, thread-safe through an internal lock.

    Duck-compatible with the legacy contract: log_event(), set_beacon_state().
    """

    def __init__(self, path: str | Path = "clickfix.db") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self.path), check_same_thread=False, timeout=30.0
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    # ─── plumbing ───
    @classmethod
    def open(cls, path: str | Path | None = None) -> Store:
        return cls(path or "clickfix.db")

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ─── campaigns ───
    def create_campaign(
        self,
        name: str,
        scenario: str = "browser_update",
        base_url: str = "",
        meta: dict[str, Any] | None = None,
    ) -> str:
        cid = new_token(10)
        with self._tx() as c:
            c.execute(
                "INSERT INTO campaigns (id, name, scenario, base_url, "
                "created_at, meta) VALUES (?,?,?,?,?,?)",
                (
                    cid,
                    name,
                    scenario,
                    base_url,
                    time.time(),
                    json.dumps(meta or {}, ensure_ascii=False),
                ),
            )
        return cid

    def get_campaign_by_id(self, cid: str) -> dict[str, Any] | None:
        row = self._find("SELECT * FROM campaigns WHERE id=?", (cid,))
        return dict(row) if row else None

    def get_campaign_by_name(self, name: str) -> dict[str, Any] | None:
        row = self._find("SELECT * FROM campaigns WHERE name=?", (name,))
        return dict(row) if row else None

    def get_campaign(self, ref: str) -> dict[str, Any] | None:
        """CLI refs accept an id or a name — id probe first, name fallback."""
        return self.get_campaign_by_id(ref) or self.get_campaign_by_name(ref)

    def count_campaigns(self) -> int:
        row = self._find("SELECT COUNT(*) AS n FROM campaigns", ())
        return int(row["n"]) if row else 0

    def list_campaigns(self) -> list[dict[str, Any]]:
        return [
            dict(r)
            for r in self._all(
                "SELECT * FROM campaigns ORDER BY created_at DESC"
            )
        ]

    def set_campaign_field(self, cid: str, field: str, value: str) -> None:
        if field not in ("name", "scenario", "base_url"):
            raise ValueError(f"immutable/unknown field: {field}")
        with self._tx() as c:
            c.execute(
                f"UPDATE campaigns SET {field}=? WHERE id=?", (value, cid)
            )

    def _find(self, sql: str, args: tuple) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, args).fetchone()

    def _all(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, args).fetchall()

    # ─── targets ───
    @staticmethod
    def _target_values(
        campaign_id: str,
        email: str,
        label: str,
        meta: dict[str, Any] | None,
        token: str,
        now: float,
    ) -> tuple[Any, ...]:
        return (
            campaign_id,
            token,
            label or email.split("@")[0] or token[:6],
            email,
            now,
            json.dumps(meta or {}, ensure_ascii=False),
        )

    def add_target(
        self,
        campaign_id: str,
        email: str = "",
        label: str = "",
        meta: dict[str, Any] | None = None,
    ) -> str:
        token = new_token(16)
        with self._tx() as c:
            c.execute(
                "INSERT INTO targets (campaign_id, token, label, email, "
                "created_at, meta) VALUES (?,?,?,?,?,?)",
                self._target_values(campaign_id, email, label, meta, token,
                                    time.time()),
            )
        return token

    def add_targets(self, rows: Iterable[dict[str, Any]]) -> list[str]:
        """Bulk insert — one transaction for the whole batch. Each row needs
        campaign_id; email/label/meta are optional like add_target()."""
        now = time.time()
        prepared: list[tuple[Any, ...]] = []
        tokens: list[str] = []
        for row in rows:
            token = new_token(16)
            tokens.append(token)
            prepared.append(
                self._target_values(
                    str(row["campaign_id"]),
                    str(row.get("email") or ""),
                    str(row.get("label") or ""),
                    row.get("meta"),
                    token,
                    now,
                )
            )
        if prepared:
            with self._tx() as c:
                c.executemany(
                    "INSERT INTO targets (campaign_id, token, label, email, "
                    "created_at, meta) VALUES (?,?,?,?,?,?)",
                    prepared,
                )
        return tokens

    def get_target(self, token: str) -> dict[str, Any] | None:
        row = self._find("SELECT * FROM targets WHERE token=?", (token,))
        return dict(row) if row else None

    def targets(self, campaign_id: str) -> list[dict[str, Any]]:
        return [
            dict(r)
            for r in self._all(
                "SELECT * FROM targets WHERE campaign_id=? ORDER BY id",
                (campaign_id,),
            )
        ]

    def count_targets(self, campaign_id: str) -> int:
        row = self._find(
            "SELECT COUNT(*) AS n FROM targets WHERE campaign_id=?",
            (campaign_id,),
        )
        return int(row["n"]) if row else 0

    def set_status(self, token: str, status: str) -> None:
        if status not in VALID_STATUSES:
            raise ValueError(
                f"bad status {status!r}, expected one of {VALID_STATUSES}"
            )
        with self._tx() as c:
            c.execute(
                "UPDATE targets SET status=? WHERE token=?", (status, token)
            )

    def set_status_many(self, tokens: list[str], status: str) -> int:
        """One UPDATE per 500-token chunk (SQLite variable ceiling), single
        transaction. Returns the number of tokens submitted."""
        if status not in VALID_STATUSES:
            raise ValueError(
                f"bad status {status!r}, expected one of {VALID_STATUSES}"
            )
        if not tokens:
            return 0
        with self._tx() as c:
            for start in range(0, len(tokens), 500):
                part = tokens[start:start + 500]
                c.execute(
                    "UPDATE targets SET status=? WHERE token IN "
                    f"({','.join('?' * len(part))})",
                    (status, *part),
                )
        return len(tokens)

    # ─── events / beacons ───
    @staticmethod
    def _event_values(
        beacon_id: str,
        campaign_id: str,
        kind: str,
        payload: str,
        created_at: float | None = None,
    ) -> tuple[Any, ...]:
        if not isinstance(payload, str):
            payload = json.dumps(payload, ensure_ascii=False, default=str)
        return (
            campaign_id,
            beacon_id or "",
            kind,
            payload[:4000],
            created_at if created_at is not None else time.time(),
        )

    def log_event(
        self,
        beacon_id: str,
        campaign_id: str,
        kind: str,
        payload: str = "",
    ) -> None:
        with self._tx() as c:
            c.execute(
                "INSERT INTO events (campaign_id, beacon_id, kind, payload, "
                "created_at) VALUES (?,?,?,?,?)",
                self._event_values(beacon_id, campaign_id, kind, payload),
            )

    def log_events(self, rows: Iterable[dict[str, Any]]) -> int:
        """Bulk insert — keys mirror log_event() (beacon_id, campaign_id,
        kind, payload), created_at optional. One transaction for the batch."""
        now = time.time()
        prepared = [
            self._event_values(
                str(row.get("beacon_id") or ""),
                str(row.get("campaign_id") or ""),
                str(row.get("kind") or ""),
                row.get("payload", ""),
                float(row["created_at"]) if row.get("created_at") is not None
                else now,
            )
            for row in rows
        ]
        if prepared:
            with self._tx() as c:
                c.executemany(
                    "INSERT INTO events (campaign_id, beacon_id, kind, "
                    "payload, created_at) VALUES (?,?,?,?,?)",
                    prepared,
                )
        return len(prepared)

    def events(
        self, campaign_id: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        return [
            dict(r)
            for r in self._all(
                "SELECT campaign_id, beacon_id, kind, payload, created_at "
                "FROM events WHERE campaign_id=? "
                "ORDER BY id DESC LIMIT ?",
                (campaign_id, limit),
            )
        ]

    def set_beacon_state(self, beacon_id: str, state: str, cid: str = "") -> None:
        with self._tx() as c:
            c.execute(
                "INSERT INTO beacons (beacon_id, campaign_id, state, updated_at) "
                "VALUES (?,?,?,?) "
                "ON CONFLICT(beacon_id) DO UPDATE SET state=excluded.state, "
                "updated_at=excluded.updated_at",
                (beacon_id, cid, state, time.time()),
            )

    def get_beacon_state(self, beacon_id: str) -> str | None:
        row = self._find(
            "SELECT state FROM beacons WHERE beacon_id=?", (beacon_id,)
        )
        return str(row["state"]) if row else None

    # ─── hits (server side) ───
    _HIT_COLS = "h.token, h.kind, h.ip, h.ua, h.referer, h.extra, h.created_at"

    @staticmethod
    def _hit_values(
        token: str,
        kind: str,
        ip: str,
        ua: str,
        referer: str,
        extra: dict[str, Any] | None,
        created_at: float | None = None,
    ) -> tuple[Any, ...]:
        if not isinstance(extra, str):
            extra = json.dumps(extra or {}, ensure_ascii=False)
        return (
            token,
            kind,
            ip[:64],
            ua[:512],
            referer[:512],
            extra[:1000],
            created_at if created_at is not None else time.time(),
        )

    def record_hit(
        self,
        token: str,
        kind: str,
        ip: str = "",
        ua: str = "",
        referer: str = "",
        extra: dict[str, Any] | None = None,
    ) -> None:
        with self._tx() as c:
            c.execute(
                "INSERT INTO hits (token, kind, ip, ua, referer, extra, "
                "created_at) VALUES (?,?,?,?,?,?,?)",
                self._hit_values(token, kind, ip, ua, referer, extra),
            )

    def record_hits(self, rows: Iterable[dict[str, Any]]) -> int:
        """Bulk insert — keys mirror record_hit() (token, kind, ip, ua,
        referer, extra), created_at optional. One transaction for the batch."""
        now = time.time()
        prepared = [
            self._hit_values(
                str(row.get("token") or ""),
                str(row.get("kind") or ""),
                str(row.get("ip") or ""),
                str(row.get("ua") or ""),
                str(row.get("referer") or ""),
                row.get("extra"),
                float(row["created_at"]) if row.get("created_at") is not None
                else now,
            )
            for row in rows
        ]
        if prepared:
            with self._tx() as c:
                c.executemany(
                    "INSERT INTO hits (token, kind, ip, ua, referer, extra, "
                    "created_at) VALUES (?,?,?,?,?,?,?)",
                    prepared,
                )
        return len(prepared)

    def hits(self, token: str) -> list[dict[str, Any]]:
        return [
            dict(r)
            for r in self._all(
                "SELECT token, kind, ip, ua, referer, extra, created_at "
                "FROM hits WHERE token=? ORDER BY id",
                (token,),
            )
        ]

    def campaign_hits(self, campaign_id: str) -> list[dict[str, Any]]:
        """Every hit of every target in the campaign, one round-trip."""
        return [
            dict(r)
            for r in self._all(
                f"SELECT {self._HIT_COLS} FROM hits h "
                "JOIN targets t ON t.token = h.token "
                "WHERE t.campaign_id=? ORDER BY h.id",
                (campaign_id,),
            )
        ]

    def campaign_hits_since(
        self, campaign_id: str, cutoff_ts: float
    ) -> list[dict[str, Any]]:
        """Campaign hits with created_at >= cutoff_ts, filtered in SQL."""
        return [
            dict(r)
            for r in self._all(
                f"SELECT {self._HIT_COLS} FROM hits h "
                "JOIN targets t ON t.token = h.token "
                "WHERE t.campaign_id=? AND h.created_at>=? ORDER BY h.id",
                (campaign_id, cutoff_ts),
            )
        ]

    # ─── reporting ───
    def status(self, campaign_id: str) -> dict[str, Any]:
        camp = self.get_campaign(campaign_id)
        if not camp:
            return {"error": f"unknown campaign: {campaign_id}"}
        rows = self._all(
            "SELECT status, COUNT(*) AS n FROM targets WHERE campaign_id=? "
            "GROUP BY status",
            (camp["id"],),
        )
        counts = {str(r["status"]): int(r["n"]) for r in rows}
        hit_rows = self._all(
            "SELECT h.kind, COUNT(*) AS n FROM hits h "
            "JOIN targets t ON t.token = h.token "
            "WHERE t.campaign_id=? GROUP BY h.kind",
            (camp["id"],),
        )
        recent = self._all(
            "SELECT h.token, h.kind, h.ip, h.created_at FROM hits h "
            "JOIN targets t ON t.token = h.token "
            "WHERE t.campaign_id=? ORDER BY h.id DESC LIMIT 10",
            (camp["id"],),
        )
        return {
            "campaign": camp,
            "targets": sum(counts.values()),
            "by_status": counts,
            "hits": {str(r["kind"]): int(r["n"]) for r in hit_rows},
            "last_events": self.events(camp["id"], 10),
            "last_hits": [dict(r) for r in recent],
        }

    def timeline(self, campaign_id: str, limit: int = 300) -> list[dict[str, Any]]:
        """Gophish-style per-campaign feed — hits and events merged into one
        stream, newest first, each row tagged with the target it belongs to.
        Bounded both by SQL LIMIT and a hard ceiling on the limit argument."""
        camp = self.get_campaign(campaign_id)
        if not camp:
            return []
        cap = max(1, min(limit, 500))
        rows = self._all(
            "SELECT h.token, h.kind, h.ip, h.ua, h.extra, h.created_at "
            "FROM hits h JOIN targets t ON t.token = h.token "
            "WHERE t.campaign_id=? ORDER BY h.id DESC LIMIT ?",
            (camp["id"], cap),
        )
        feed: list[dict[str, Any]] = [
            {
                "ts": float(r["created_at"]),
                "kind": str(r["kind"]),
                "source": "hit",
                "token": str(r["token"]),
                "ip": str(r["ip"]),
                "ua": str(r["ua"]),
                "payload": str(r["extra"] or ""),
            }
            for r in rows
        ]
        for r in self._all(
            "SELECT beacon_id, kind, payload, created_at FROM events "
            "WHERE campaign_id=? ORDER BY id DESC LIMIT ?",
            (camp["id"], cap),
        ):
            feed.append(
                {
                    "ts": float(r["created_at"]),
                    "kind": str(r["kind"]),
                    "source": "event",
                    "token": "",
                    "ip": "",
                    "ua": "",
                    "payload": str(r["payload"] or ""),
                }
            )
        feed.sort(key=lambda e: e["ts"], reverse=True)
        feed = feed[:cap]
        identities = {t["token"]: t for t in self.targets(camp["id"])}
        for e in feed:
            tgt = identities.get(e["token"])
            e["email"] = str(tgt["email"]) if tgt else ""
            e["label"] = str(tgt["label"]) if tgt else ""
            e["status"] = str(tgt["status"]) if tgt else ""
        return feed

    # ─── sending profiles (smtp) ───
    def set_send_profile(self, name: str, config: dict[str, Any]) -> None:
        if not name.strip():
            raise ValueError("profile name must not be empty")
        with self._tx() as c:
            c.execute(
                "INSERT INTO send_profiles (name, config, created_at) "
                "VALUES (?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET config=excluded.config",
                (name, json.dumps(config, ensure_ascii=False), time.time()),
            )

    def get_send_profile(self, name: str) -> dict[str, Any] | None:
        row = self._find(
            "SELECT config FROM send_profiles WHERE name=?", (name,)
        )
        if not row:
            return None
        try:
            config = json.loads(str(row["config"]))
        except ValueError:
            return None
        return config if isinstance(config, dict) else None

    def list_send_profiles(self) -> list[dict[str, Any]]:
        return [
            {"name": str(r["name"]), "config": json.loads(str(r["config"]))}
            for r in self._all(
                "SELECT name, config FROM send_profiles ORDER BY name"
            )
        ]

    def remove_send_profile(self, name: str) -> bool:
        with self._tx() as c:
            cur = c.execute(
                "DELETE FROM send_profiles WHERE name=?", (name,)
            )
        return cur.rowcount > 0

    # ─── outbound webhooks ───

    def list_webhooks(self) -> list[str]:
        return [
            str(r["url"])
            for r in self._all("SELECT url FROM webhooks ORDER BY id")
        ]

    def add_webhook(self, url: str) -> None:
        cleaned = url.strip()
        if not cleaned.startswith(("http://", "https://")):
            raise ValueError("webhook url must be http(s)://")
        with self._tx() as c:
            c.execute("INSERT OR IGNORE INTO webhooks (url) VALUES (?)", (cleaned,))

    def remove_webhook(self, url: str) -> bool:
        with self._tx() as c:
            cur = c.execute("DELETE FROM webhooks WHERE url=?", (url.strip(),))
        return cur.rowcount > 0

    def proxy_sessions(self, limit: int = 100) -> list[dict[str, Any]]:
        """Captured proxy artefacts — forms and cookies, newest first."""
        return [
            {
                "kind": str(r["kind"]),
                "payload": json.loads(str(r["payload"] or "{}")),
                "at": float(r["created_at"]),
            }
            for r in self._all(
                "SELECT kind, payload, created_at FROM events "
                "WHERE campaign_id='' AND kind LIKE 'proxy:%' "
                "ORDER BY id DESC LIMIT ?",
                (max(1, min(int(limit), 500)),),
            )
        ]
