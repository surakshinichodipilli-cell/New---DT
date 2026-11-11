import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql://" + DATABASE_URL[len("postgres://"):]
if DATABASE_URL and not DATABASE_URL.startswith("postgresql://"):
    raise ValueError("DATABASE_URL must use the PostgreSQL postgresql:// scheme.")

DB_PATH = Path(os.getenv("DATABASE_PATH", Path(__file__).resolve().parent / "netshield.db"))
_POSTGRES_PLACEHOLDER = re.compile(r"\?")
_POSTGRES_SCHEMA_INFO = re.compile(r"^\s*PRAGMA\s+table_info\((\w+)\)\s*;?\s*$", re.IGNORECASE)


def _postgres_query(query):
    schema_info = _POSTGRES_SCHEMA_INFO.match(query)
    if schema_info:
        return (
            "SELECT column_name AS name FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = %s ORDER BY ordinal_position"
        ), (schema_info.group(1).lower(),)

    query = query.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
    query = query.replace("user_id INTEGER NOT NULL", "user_id BIGINT NOT NULL")
    query = re.sub(
        r"date\(([\w.]+)\)\s*>=\s*date\(\?\)",
        r"CAST(\1 AS DATE) >= CAST(? AS DATE)",
        query,
        flags=re.IGNORECASE,
    )
    query = re.sub(
        r"substr\(([\w.]+),\s*1,\s*10\)",
        r"to_char(\1, 'YYYY-MM-DD')",
        query,
        flags=re.IGNORECASE,
    )
    query = re.sub(r"datetime\(([\w.]+)\)", r"\1", query, flags=re.IGNORECASE)
    query = re.sub(
        r"ORDER BY\s+([\w.]+)\s+COLLATE\s+NOCASE",
        r"ORDER BY lower(\1)",
        query,
        flags=re.IGNORECASE,
    )
    return _POSTGRES_PLACEHOLDER.sub("%s", query), ()


def _normalize_postgres_row(row):
    if row is None:
        return None
    return {
        key: value.isoformat(sep=" ") if isinstance(value, datetime) else value
        for key, value in row.items()
    }


class _PostgresCursor:
    def __init__(self, cursor):
        self._cursor = cursor

    def fetchone(self):
        return _normalize_postgres_row(self._cursor.fetchone())

    def fetchall(self):
        return [_normalize_postgres_row(row) for row in self._cursor.fetchall()]

    @property
    def rowcount(self):
        return self._cursor.rowcount


class _PostgresConnection:
    def __init__(self, connection):
        self._connection = connection

    def __enter__(self):
        return self

    def __exit__(self, exc_type, _exc_value, _traceback):
        try:
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
        finally:
            self._connection.close()

    def execute(self, query, parameters=()):
        query, implicit_parameters = _postgres_query(query)
        if implicit_parameters:
            parameters = implicit_parameters
        return _PostgresCursor(self._connection.execute(query, parameters))

    def commit(self):
        self._connection.commit()

    def rollback(self):
        self._connection.rollback()


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, _exc_value, _traceback):
        try:
            return super().__exit__(exc_type, _exc_value, _traceback)
        finally:
            self.close()


def get_db_connection():
    if DATABASE_URL:
        import psycopg
        from psycopg.rows import dict_row

        return _PostgresConnection(
            psycopg.connect(DATABASE_URL, row_factory=dict_row)
        )

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, factory=_ClosingConnection)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with get_db_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                theme TEXT DEFAULT 'dark',
                notification_settings TEXT DEFAULT 'email',
                network_settings TEXT DEFAULT 'monitor-authorized',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS url_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                indicators TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                mac_address TEXT,
                hostname TEXT,
                status TEXT NOT NULL,
                classification TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS network_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                total_devices INTEGER NOT NULL,
                new_devices INTEGER NOT NULL,
                suspicious_devices INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                mode TEXT NOT NULL DEFAULT 'live',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                recommended_action TEXT NOT NULL DEFAULT '',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'new',
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS device_inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                device_key TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                mac_address TEXT,
                hostname TEXT,
                classification TEXT NOT NULL,
                first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                mode TEXT NOT NULL DEFAULT 'live',
                UNIQUE (user_id, device_key),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS trusted_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                device_key TEXT NOT NULL,
                label TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (user_id, device_key),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )

        columns = {row["name"] for row in conn.execute("PRAGMA table_info(network_scans)").fetchall()}
        if "mode" not in columns:
            conn.execute("ALTER TABLE network_scans ADD COLUMN mode TEXT NOT NULL DEFAULT 'live'")

        user_columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "network_mode" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN network_mode TEXT NOT NULL DEFAULT 'demo'")
        alert_columns = {row["name"] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        if "recommended_action" not in alert_columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN recommended_action TEXT NOT NULL DEFAULT ''")

        conn.commit()


def register_user(full_name, email, username, password_hash):
    with get_db_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO users (full_name, email, username, password_hash) VALUES (?, ?, ?, ?) RETURNING id",
            (full_name, email.lower(), username.lower(), password_hash),
        )
        user_id = cursor.fetchone()["id"]
        conn.commit()
        return user_id


def get_user_by_id(user_id):
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def get_user_by_username_or_email(identifier):
    normalized = identifier.strip().lower()
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?",
            (normalized, normalized),
        ).fetchone()
        return dict(row) if row else None


def get_user_by_email(email):
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE LOWER(email) = ?", (email.lower(),)).fetchone()
        return dict(row) if row else None


def get_user_by_username(username):
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE LOWER(username) = ?", (username.lower(),)).fetchone()
        return dict(row) if row else None


def save_url_scan(user_id, url, risk_score, risk_level, indicators):
    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO url_scans (user_id, url, risk_score, risk_level, indicators) VALUES (?, ?, ?, ?, ?)",
            (user_id, url, risk_score, risk_level, " | ".join(indicators)),
        )
        conn.commit()


def get_url_scans_for_user(user_id):
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM url_scans WHERE user_id = ? ORDER BY created_at DESC, id DESC",
            (user_id,),
        ).fetchall()
        return [dict(row) for row in rows]


def save_network_scan(user_id, total_devices, new_devices, suspicious_devices, risk_score, risk_level, mode="live"):
    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO network_scans (user_id, total_devices, new_devices, suspicious_devices, risk_score, risk_level, mode) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, total_devices, new_devices, suspicious_devices, risk_score, risk_level, mode),
        )
        conn.commit()


def save_device(user_id, ip_address, mac_address, hostname, status, classification):
    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO devices (user_id, ip_address, mac_address, hostname, status, classification) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, ip_address, mac_address, hostname, status, classification),
        )
        conn.commit()


def get_devices_for_user(user_id):
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM devices WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()
        return [dict(row) for row in rows]


def record_discovered_device(user_id, device, mode="live"):
    ip_address = device.get("ip", "")
    mac_address = device.get("mac", "")
    key_value = mac_address.lower() if mac_address and mac_address != "--" else ip_address
    device_key = f"{mode}:{key_value.lower()}"
    with get_db_connection() as conn:
        trusted = conn.execute(
            """
            SELECT label FROM trusted_devices
            WHERE user_id = ? AND device_key IN (?, ?)
            LIMIT 1
            """,
            (user_id, key_value.lower(), ip_address.lower()),
        ).fetchone()
        previous = conn.execute(
            "SELECT id FROM device_inventory WHERE user_id = ? AND device_key = ?",
            (user_id, device_key),
        ).fetchone()
        classification = "TRUSTED" if trusted and mode == "live" else (
            "DEMO" if mode == "demo" else ("UNKNOWN" if previous else "NEW")
        )
        conn.execute(
            """
            INSERT INTO device_inventory
                (user_id, device_key, ip_address, mac_address, hostname, classification, mode)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, device_key) DO UPDATE SET
                ip_address = excluded.ip_address,
                mac_address = excluded.mac_address,
                hostname = excluded.hostname,
                classification = excluded.classification,
                last_seen = CURRENT_TIMESTAMP
            """,
            (
                user_id, device_key, ip_address, mac_address,
                device.get("hostname", "Unavailable"), classification, mode,
            ),
        )
        conn.commit()
        return previous is None, classification


def get_device_inventory(user_id, mode=None):
    query = """
        SELECT di.*,
               (SELECT td.label FROM trusted_devices td
                WHERE td.user_id = di.user_id
                  AND (td.device_key = lower(di.mac_address)
                       OR td.device_key = lower(di.ip_address))
                ORDER BY td.id LIMIT 1) AS trusted_label
        FROM device_inventory di
        WHERE di.user_id = ?
    """
    values = [user_id]
    if mode:
        query += " AND di.mode = ?"
        values.append(mode)
    query += " ORDER BY di.last_seen DESC"
    with get_db_connection() as conn:
        return [dict(row) for row in conn.execute(query, tuple(values)).fetchall()]


def get_trusted_devices(user_id):
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT device_key, label, created_at FROM trusted_devices WHERE user_id = ? ORDER BY label COLLATE NOCASE",
            (user_id,),
        ).fetchall()
        return [dict(row) for row in rows]


def trust_device(user_id, device_key, label):
    normalized_key = device_key.strip().lower()
    if not normalized_key or not label.strip():
        raise ValueError("A device identifier and display name are required.")
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO trusted_devices (user_id, device_key, label)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id, device_key) DO UPDATE SET label = excluded.label
            """,
            (user_id, normalized_key, label.strip()[:80]),
        )
        conn.execute(
            """
            UPDATE device_inventory SET classification = 'TRUSTED'
            WHERE user_id = ? AND mode = 'live'
              AND (lower(mac_address) = ? OR lower(ip_address) = ?)
            """,
            (user_id, normalized_key, normalized_key),
        )
        conn.commit()


def remove_trusted_device(user_id, device_key):
    normalized_key = device_key.strip().lower()
    with get_db_connection() as conn:
        conn.execute(
            "DELETE FROM trusted_devices WHERE user_id = ? AND device_key = ?",
            (user_id, normalized_key),
        )
        conn.execute(
            """
            UPDATE device_inventory SET classification = 'UNKNOWN'
            WHERE user_id = ? AND mode = 'live'
              AND (lower(mac_address) = ? OR lower(ip_address) = ?)
            """,
            (user_id, normalized_key, normalized_key),
        )
        conn.commit()


def get_url_scan_history(user_id, limit=200):
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM url_scans WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT ?",
            (user_id, max(1, min(int(limit), 500))),
        ).fetchall()
        return [dict(row) for row in rows]


def delete_url_scan_history(user_id):
    with get_db_connection() as conn:
        conn.execute("DELETE FROM url_scans WHERE user_id = ?", (user_id,))
        conn.commit()


def get_filtered_alerts(user_id, severity=None, event_type=None):
    query = "SELECT * FROM alerts WHERE user_id = ?"
    values = [user_id]
    if severity:
        query += " AND severity = ?"
        values.append(severity)
    if event_type:
        query += " AND alert_type = ?"
        values.append(event_type)
    query += " ORDER BY timestamp DESC, id DESC LIMIT 500"
    with get_db_connection() as conn:
        return [dict(row) for row in conn.execute(query, tuple(values)).fetchall()]


def add_alert(user_id, alert_type, severity, description, status="new", recommended_action=""):
    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO alerts (user_id, alert_type, severity, description, status, recommended_action) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, alert_type, severity, description, status, recommended_action),
        )
        conn.commit()


def get_alerts_for_user(user_id):
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE user_id = ? ORDER BY timestamp DESC, id DESC",
            (user_id,),
        ).fetchall()
        return [dict(row) for row in rows]


def update_alert_status(alert_id, user_id, status):
    with get_db_connection() as conn:
        cursor = conn.execute(
            "UPDATE alerts SET status = ? WHERE id = ? AND user_id = ?",
            (status, alert_id, user_id),
        )
        conn.commit()
        return cursor.rowcount > 0


def delete_alert(alert_id, user_id):
    with get_db_connection() as conn:
        cursor = conn.execute("DELETE FROM alerts WHERE id = ? AND user_id = ?", (alert_id, user_id))
        conn.commit()
        return cursor.rowcount > 0


def get_dashboard_stats(user_id):
    with get_db_connection() as conn:
        url_scan_count = conn.execute("SELECT COUNT(*) as count FROM url_scans WHERE user_id = ?", (user_id,)).fetchone()["count"]
        high_risk_urls = conn.execute("SELECT COUNT(*) as count FROM url_scans WHERE user_id = ? AND risk_score >= 71", (user_id,)).fetchone()["count"]
        safe_urls = conn.execute("SELECT COUNT(*) as count FROM url_scans WHERE user_id = ? AND risk_score < 31", (user_id,)).fetchone()["count"]
        suspicious_urls = conn.execute("SELECT COUNT(*) as count FROM url_scans WHERE user_id = ? AND risk_score >= 31 AND risk_score < 71", (user_id,)).fetchone()["count"]
        latest_url_score = conn.execute(
            "SELECT risk_score FROM url_scans WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT 1",
            (user_id,),
        ).fetchone()
        latest_network_score = conn.execute(
            "SELECT risk_score FROM network_scans WHERE user_id = ? AND mode = 'live' ORDER BY created_at DESC, id DESC LIMIT 1",
            (user_id,),
        ).fetchone()
        latest_network_scan = conn.execute(
            """
            SELECT total_devices, new_devices, suspicious_devices, risk_level, mode, created_at
            FROM network_scans WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT 1
            """,
            (user_id,),
        ).fetchone()
        total_devices = conn.execute(
            "SELECT COUNT(*) AS count FROM device_inventory WHERE user_id = ?",
            (user_id,),
        ).fetchone()["count"]
        known_devices = conn.execute("SELECT COUNT(*) as count FROM device_inventory WHERE user_id = ? AND classification = 'TRUSTED'", (user_id,)).fetchone()["count"]
        new_devices = conn.execute("SELECT COUNT(*) as count FROM device_inventory WHERE user_id = ? AND classification = 'NEW'", (user_id,)).fetchone()["count"]
        suspicious_devices = conn.execute("SELECT COUNT(*) as count FROM device_inventory WHERE user_id = ? AND classification = 'SUSPICIOUS'", (user_id,)).fetchone()["count"]
        unknown_devices = conn.execute("SELECT COUNT(*) as count FROM device_inventory WHERE user_id = ? AND classification = 'UNKNOWN'", (user_id,)).fetchone()["count"]
        demo_devices = conn.execute("SELECT COUNT(*) as count FROM device_inventory WHERE user_id = ? AND classification = 'DEMO'", (user_id,)).fetchone()["count"]
        active_alerts = conn.execute(
            "SELECT COUNT(*) as count FROM alerts WHERE user_id = ? AND status NOT IN ('reviewed', 'resolved')",
            (user_id,),
        ).fetchone()["count"]
        alert_count = conn.execute(
            "SELECT COUNT(*) AS count FROM alerts WHERE user_id = ?",
            (user_id,),
        ).fetchone()["count"]
        high_active_alerts = conn.execute(
            """
            SELECT COUNT(*) AS count FROM alerts
            WHERE user_id = ? AND status NOT IN ('reviewed', 'resolved')
              AND lower(severity) IN ('high', 'critical')
            """,
            (user_id,),
        ).fetchone()["count"]
        medium_active_alerts = conn.execute(
            """
            SELECT COUNT(*) AS count FROM alerts
            WHERE user_id = ? AND status NOT IN ('reviewed', 'resolved')
              AND lower(severity) = 'medium'
            """,
            (user_id,),
        ).fetchone()["count"]
        recent_events = conn.execute(
            "SELECT alert_type, severity, description, timestamp, status FROM alerts WHERE user_id = ? ORDER BY timestamp DESC, id DESC LIMIT 5",
            (user_id,),
        ).fetchall()

    risk_scores = []
    if latest_url_score:
        risk_scores.append(latest_url_score["risk_score"])
    if latest_network_score:
        risk_scores.append(latest_network_score["risk_score"])
    avg_risk = int(sum(risk_scores) / len(risk_scores)) if risk_scores else 0
    has_scan_data = bool(risk_scores)
    if avg_risk >= 71 or high_active_alerts:
        security_status = "HIGH RISK"
    elif avg_risk >= 31 or medium_active_alerts:
        security_status = "MEDIUM RISK"
    elif has_scan_data:
        security_status = "LOW RISK"
    else:
        security_status = "NO SCAN DATA"

    if has_scan_data:
        security_explanation = f"Latest saved URL and live network scans average {avg_risk}/100 risk."
        if high_active_alerts or medium_active_alerts:
            security_explanation += (
                f" {high_active_alerts + medium_active_alerts} high- or medium-severity "
                "alert(s) remain unresolved."
            )
        security_explanation += " These estimates do not guarantee safety."
    elif high_active_alerts or medium_active_alerts:
        security_explanation = "An unresolved security alert needs review; run a scan to establish a current estimate."
    else:
        security_explanation = "Run a URL or network scan to establish an initial risk estimate."

    return {
        "overall_risk_score": avg_risk,
        "overall_security_score": 100 - avg_risk if has_scan_data else None,
        "security_status": security_status,
        "security_explanation": security_explanation,
        "has_scan_data": has_scan_data,
        "has_activity_data": bool(url_scan_count or latest_network_scan or total_devices or alert_count),
        "urls_scanned": url_scan_count,
        "safe_urls": safe_urls,
        "suspicious_urls": suspicious_urls,
        "high_risk_urls": high_risk_urls,
        "total_devices": total_devices,
        "unverified_devices": new_devices + unknown_devices,
        "known_devices": known_devices,
        "new_devices": new_devices,
        "unknown_devices": unknown_devices,
        "demo_devices": demo_devices,
        "suspicious_devices": suspicious_devices,
        "latest_network_scan": dict(latest_network_scan) if latest_network_scan else None,
        "active_alerts": active_alerts,
        "recent_events": [dict(row) for row in recent_events],
        "latest_url_score": latest_url_score["risk_score"] if latest_url_score else 0,
        "latest_network_score": latest_network_score["risk_score"] if latest_network_score else 0,
    }


def get_activity_for_user(user_id, days=7):
    days = max(1, min(int(days), 90))
    today = datetime.now(timezone.utc).date()
    start_day = today - timedelta(days=days - 1)
    counts = {
        (start_day + timedelta(days=offset)).isoformat(): {
            "urls": 0,
            "high_risk_urls": 0,
            "network_scans": 0,
            "device_discoveries": 0,
            "alerts": 0,
        }
        for offset in range(days)
    }
    with get_db_connection() as conn:
        url_rows = conn.execute(
            """
            SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS count,
                   SUM(CASE WHEN risk_score >= 71 THEN 1 ELSE 0 END) AS high_risk_count
            FROM url_scans
            WHERE user_id = ? AND date(created_at) >= date(?)
            GROUP BY substr(created_at, 1, 10)
            """,
            (user_id, start_day.isoformat()),
        ).fetchall()
        network_rows = conn.execute(
            """
            SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS count
            FROM network_scans
            WHERE user_id = ? AND date(created_at) >= date(?)
            GROUP BY substr(created_at, 1, 10)
            """,
            (user_id, start_day.isoformat()),
        ).fetchall()
        device_rows = conn.execute(
            """
            SELECT substr(first_seen, 1, 10) AS day, COUNT(*) AS count
            FROM device_inventory
            WHERE user_id = ? AND date(first_seen) >= date(?)
            GROUP BY substr(first_seen, 1, 10)
            """,
            (user_id, start_day.isoformat()),
        ).fetchall()
        alert_rows = conn.execute(
            """
            SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS count
            FROM alerts
            WHERE user_id = ? AND date(timestamp) >= date(?)
            GROUP BY substr(timestamp, 1, 10)
            """,
            (user_id, start_day.isoformat()),
        ).fetchall()
    for row in url_rows:
        if row["day"] in counts:
            counts[row["day"]]["urls"] = row["count"]
            counts[row["day"]]["high_risk_urls"] = row["high_risk_count"]
    for row in network_rows:
        if row["day"] in counts:
            counts[row["day"]]["network_scans"] = row["count"]
    for row in device_rows:
        if row["day"] in counts:
            counts[row["day"]]["device_discoveries"] = row["count"]
    for row in alert_rows:
        if row["day"] in counts:
            counts[row["day"]]["alerts"] = row["count"]
    return [
        {"date": day, **values}
        for day, values in counts.items()
    ]


def get_dashboard_events(user_id, limit=10):
    with get_db_connection() as conn:
        rows = conn.execute(
            """
            SELECT event_type, description, risk_level, event_time, status
            FROM (
                SELECT 'URL scan' AS event_type,
                       'Analyzed ' || url AS description,
                       CASE
                           WHEN risk_score >= 71 THEN 'HIGH'
                           WHEN risk_score >= 31 THEN 'MEDIUM'
                           ELSE 'LOW'
                       END AS risk_level,
                       created_at AS event_time,
                       'Analyzed' AS status,
                       id AS event_id,
                       1 AS event_priority
                FROM url_scans WHERE user_id = ?
                UNION ALL
                SELECT CASE WHEN mode = 'demo' THEN 'Network scan (demo)' ELSE 'Network scan' END,
                       CAST(total_devices AS TEXT) || ' devices detected; ' ||
                           CAST(new_devices AS TEXT) || ' new and ' ||
                           CAST(suspicious_devices AS TEXT) || ' suspicious.',
                       risk_level, created_at, 'Recorded', id, 2
                FROM network_scans WHERE user_id = ?
                UNION ALL
                SELECT alert_type, description, severity, timestamp, status, id, 3
                FROM alerts WHERE user_id = ?
            )
            ORDER BY datetime(event_time) DESC, event_priority DESC, event_id DESC
            LIMIT ?
            """,
            (user_id, user_id, user_id, max(1, min(int(limit), 100))),
        ).fetchall()
        return [dict(row) for row in rows]


def update_user_settings(
    user_id,
    full_name=None,
    email=None,
    theme=None,
    notification_settings=None,
    network_settings=None,
    network_mode=None,
):
    if not any([full_name, email, theme, notification_settings, network_settings, network_mode]):
        return

    with get_db_connection() as conn:
        updates = []
        values = []

        if full_name:
            updates.append("full_name = ?")
            values.append(full_name)
        if email:
            updates.append("email = ?")
            values.append(email.lower())
        if theme:
            updates.append("theme = ?")
            values.append(theme)
        if notification_settings:
            updates.append("notification_settings = ?")
            values.append(notification_settings)
        if network_settings:
            updates.append("network_settings = ?")
            values.append(network_settings)
        if network_mode in {"demo", "live"}:
            updates.append("network_mode = ?")
            values.append(network_mode)

        values.append(user_id)
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
        conn.execute(query, tuple(values))
        conn.commit()


def update_password(user_id, password_hash):
    with get_db_connection() as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
        conn.commit()


def get_network_history_for_user(user_id):
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM network_scans WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()
        return [dict(row) for row in rows]


def get_url_history_for_user(user_id):
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM url_scans WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()
        return [dict(row) for row in rows]


def ensure_db_exists():
    init_db()
    if not DATABASE_URL and not DB_PATH.exists():
        DB_PATH.touch()
