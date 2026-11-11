import os
import socket
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timezone

_TEST_DIRECTORY = tempfile.TemporaryDirectory()
os.environ["DATABASE_PATH"] = str(Path(_TEST_DIRECTORY.name) / "netshield-test.db")
os.environ["SECRET_KEY"] = "test-session-key-for-local-unit-tests"

from app import app, _server_port_is_available
from database.db_helper import _postgres_query
from database.migrate_sqlite_to_postgres import migrate_sqlite_to_postgres
from database import db_helper
from werkzeug.security import generate_password_hash


class FlaskAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config.update(TESTING=True)
        cls.addClassCleanup(_TEST_DIRECTORY.cleanup)

    def setUp(self):
        with db_helper.get_db_connection() as conn:
            for table in (
                "alerts", "trusted_devices", "device_inventory", "devices",
                "network_scans", "url_scans", "users",
            ):
                conn.execute(f"DELETE FROM {table}")
            conn.commit()
        self.user_id = db_helper.register_user(
            "Test User", "test@example.com", "testuser",
            generate_password_hash("correct-horse-battery"),
        )
        self.client = app.test_client()
        with self.client.session_transaction() as user_session:
            user_session["user_id"] = self.user_id
            user_session["csrf_token"] = "test-csrf-token"
        self.headers = {"X-CSRF-Token": "test-csrf-token"}

    def test_private_dashboard_requires_authentication(self):
        response = app.test_client().get("/api/dashboard")
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.get_json()["success"])

    def test_server_reports_a_port_that_is_already_in_use(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            host, port = listener.getsockname()
            self.assertFalse(_server_port_is_available(host, port))

        self.assertTrue(_server_port_is_available(host, port))

    def test_postgres_query_adapter_translates_sqlite_compatibility_queries(self):
        query, parameters = _postgres_query(
            "SELECT substr(created_at, 1, 10) AS day "
            "FROM url_scans WHERE user_id = ? AND date(created_at) >= date(?)"
        )
        self.assertIn("to_char(created_at, 'YYYY-MM-DD')", query)
        self.assertIn("CAST(created_at AS DATE) >= CAST(%s AS DATE)", query)
        self.assertEqual(parameters, ())
        self.assertEqual(query.count("%s"), 2)

        schema_query, schema_parameters = _postgres_query(
            "PRAGMA table_info(network_scans)"
        )
        self.assertIn("information_schema.columns", schema_query)
        self.assertEqual(schema_parameters, ("network_scans",))

        postgres_schema, _ = _postgres_query(
            "CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "user_id INTEGER NOT NULL)"
        )
        self.assertIn("id BIGSERIAL PRIMARY KEY", postgres_schema)
        self.assertIn("user_id BIGINT NOT NULL", postgres_schema)

    def test_database_initialization_preserves_users_and_scan_history(self):
        db_helper.save_url_scan(
            self.user_id,
            "https://preserved.example",
            12,
            "SAFE",
            [],
        )

        db_helper.ensure_db_exists()

        self.assertEqual(db_helper.get_user_by_id(self.user_id)["username"], "testuser")
        history = db_helper.get_url_scan_history(self.user_id)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["url"], "https://preserved.example")

    def test_sqlite_migration_requires_a_configured_postgres_target(self):
        source_url_count = len(db_helper.get_url_scan_history(self.user_id))
        with self.assertRaisesRegex(ValueError, "DATABASE_URL"):
            migrate_sqlite_to_postgres(db_helper.DB_PATH, "")
        self.assertEqual(len(db_helper.get_url_scan_history(self.user_id)), source_url_count)

    def test_csrf_is_required_for_mutating_api(self):
        response = self.client.post("/api/scan-url", json={"url": "https://example.com"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("CSRF", response.get_json()["message"])

    def test_scan_history_persists_and_is_user_scoped(self):
        response = self.client.post(
            "/api/scan-url",
            json={"url": "https://example.com"},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["result"]["risk_level"], "SAFE")

        history = self.client.get("/api/scan-history").get_json()["scans"]
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["url"], "https://example.com")

        deleted = self.client.delete("/api/scan-history", headers=self.headers)
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(self.client.get("/api/scan-history").get_json()["scans"], [])

    def test_demo_scan_is_explicitly_labeled_and_persisted(self):
        response = self.client.post(
            "/api/network/scan",
            json={"authorized": False},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        result = response.get_json()["result"]
        self.assertEqual(result["mode"], "demo")
        self.assertTrue(all(device["classification"] == "DEMO" for device in result["devices"]))
        self.assertEqual(db_helper.get_network_history_for_user(self.user_id)[0]["mode"], "demo")

    def test_live_scan_requires_explicit_authorization(self):
        db_helper.update_user_settings(self.user_id, network_mode="live")
        response = self.client.post(
            "/api/network/scan",
            json={"authorized": False},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("authorized", response.get_json()["message"].lower())

    def test_cloud_live_network_scans_require_a_local_agent(self):
        db_helper.update_user_settings(self.user_id, network_mode="live")
        previous_deployment_setting = app.config["IS_PRODUCTION"]
        app.config["IS_PRODUCTION"] = True
        try:
            page = self.client.get("/network-scan")
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"authorized local monitoring agent", page.data)
            self.assertIn(b"no local agent is configured", page.data)

            response = self.client.post(
                "/api/network/scan",
                json={"authorized": True},
                headers=self.headers,
            )
            self.assertEqual(response.status_code, 503)
            self.assertIn("no agent is configured", response.get_json()["message"])
        finally:
            app.config["IS_PRODUCTION"] = previous_deployment_setting

    def test_alert_resolution_cannot_change_another_users_alert(self):
        other_user_id = db_helper.register_user(
            "Other User", "other@example.com", "otheruser",
            generate_password_hash("correct-horse-battery"),
        )
        db_helper.add_alert(other_user_id, "Private alert", "High", "Other account alert.")
        with db_helper.get_db_connection() as conn:
            alert_id = conn.execute(
                "SELECT id FROM alerts WHERE user_id = ?",
                (other_user_id,),
            ).fetchone()["id"]

        response = self.client.post(
            "/api/alerts/resolve",
            json={"alert_id": alert_id},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 404)
        with db_helper.get_db_connection() as conn:
            status = conn.execute(
                "SELECT status FROM alerts WHERE id = ?",
                (alert_id,),
            ).fetchone()["status"]
        self.assertEqual(status, "new")

    def test_csv_report_contains_saved_database_records(self):
        self.client.post(
            "/api/scan-url",
            json={"url": "https://example.com"},
            headers=self.headers,
        )
        response = self.client.get("/reports?download=csv")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.content_type)
        self.assertIn(b"https://example.com", response.data)

    def test_authenticated_pages_render(self):
        for path in (
            "/home", "/dashboard", "/scan-url", "/network-scan",
            "/devices", "/alerts", "/reports", "/settings",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)

    def test_dashboard_uses_saved_stats_and_combines_security_events(self):
        db_helper.save_url_scan(
            self.user_id,
            "https://example.test/login",
            82,
            "HIGH RISK",
            ["test indicator"],
        )
        db_helper.save_network_scan(
            self.user_id,
            total_devices=3,
            new_devices=2,
            suspicious_devices=1,
            risk_score=45,
            risk_level="MEDIUM",
            mode="demo",
        )
        db_helper.record_discovered_device(
            self.user_id,
            {"ip": "192.168.1.25", "mac": "aa:bb:cc:dd:ee:25", "hostname": "demo-device"},
            mode="demo",
        )
        db_helper.add_alert(self.user_id, "Test alert", "Medium", "Needs review.")

        response = self.client.get("/api/dashboard")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        stats = payload["stats"]
        self.assertEqual(stats["urls_scanned"], 1)
        self.assertEqual(stats["high_risk_urls"], 1)
        self.assertEqual(stats["total_devices"], 1)
        self.assertEqual(stats["active_alerts"], 1)
        self.assertEqual(stats["overall_security_score"], 18)
        self.assertEqual(stats["security_status"], "HIGH RISK")
        self.assertEqual(stats["latest_network_scan"]["mode"], "demo")

        event_types = [event["event_type"] for event in payload["events"]]
        self.assertIn("URL scan", event_types)
        self.assertIn("Network scan (demo)", event_types)
        self.assertIn("Test alert", event_types)
        today = next(
            item for item in payload["activity"]
            if item["date"] == datetime.now(timezone.utc).date().isoformat()
        )
        self.assertEqual(today["urls"], 1)
        self.assertEqual(today["high_risk_urls"], 1)
        self.assertEqual(today["alerts"], 1)
        self.assertIn("device_discoveries", today)

        page = self.client.get("/dashboard")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"URL SECURITY OVERVIEW", page.data)
        self.assertIn(b"WI-FI NETWORK MONITOR", page.data)
        self.assertIn(b"Test User", page.data)
        self.assertIn(b"Network scan (demo)", page.data)
        self.assertIn(b"aria-current=\"page\"", page.data)

    def test_dashboard_shows_empty_baseline_without_fabricated_risk_score(self):
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"NO SCAN DATA", response.data)
        self.assertIn(b"No security events yet", response.data)
        self.assertIn(b"No scan activity yet", response.data)
        stats = self.client.get("/api/dashboard").get_json()["stats"]
        self.assertIsNone(stats["overall_security_score"])
        self.assertFalse(stats["has_activity_data"])

    def test_dashboard_uses_newest_scan_when_timestamps_match(self):
        db_helper.save_url_scan(self.user_id, "http://192.168.1.1", 80, "HIGH RISK", [])
        db_helper.save_url_scan(self.user_id, "https://example.com", 5, "SAFE", [])
        with db_helper.get_db_connection() as conn:
            conn.execute(
                "UPDATE url_scans SET created_at = ? WHERE user_id = ?",
                ("2026-10-31 10:00:00", self.user_id),
            )
            conn.commit()

        stats = self.client.get("/api/dashboard").get_json()["stats"]
        self.assertEqual(stats["latest_url_score"], 5)
        self.assertEqual(stats["overall_security_score"], 95)

    def test_successful_login_opens_dashboard(self):
        client = app.test_client()
        client.get("/login")
        with client.session_transaction() as browser_session:
            csrf_token = browser_session["csrf_token"]
        response = client.post(
            "/login",
            data={
                "username": "testuser",
                "password": "correct-horse-battery",
                "csrf_token": csrf_token,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/dashboard")
        self.assertEqual(client.get("/dashboard").status_code, 200)

    def test_trusted_device_record_can_be_added(self):
        response = self.client.post(
            "/api/devices/trust",
            json={"identifier": "aa:bb:cc:dd:ee:ff", "label": "Office laptop"},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        trusted = db_helper.get_trusted_devices(self.user_id)
        self.assertEqual(trusted[0]["label"], "Office laptop")

    def test_trusted_ip_matches_live_device_with_mac(self):
        db_helper.trust_device(self.user_id, "192.168.4.25", "Office printer")
        _, classification = db_helper.record_discovered_device(
            self.user_id,
            {"ip": "192.168.4.25", "mac": "aa:bb:cc:dd:ee:25", "hostname": "printer"},
            mode="live",
        )
        self.assertEqual(classification, "TRUSTED")

    def test_api_reports_can_return_csv(self):
        self.client.post(
            "/api/scan-url",
            json={"url": "https://example.com"},
            headers=self.headers,
        )
        response = self.client.get("/api/reports?format=csv")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.content_type)
        self.assertIn(b"https://example.com", response.data)

    def test_registration_requires_valid_csrf_and_password(self):
        client = app.test_client()
        with client.session_transaction() as user_session:
            user_session["csrf_token"] = "registration-token"
        response = client.post(
            "/register",
            data={
                "full_name": "New User",
                "email": "new@example.com",
                "username": "newuser",
                "password": "short",
                "confirm_password": "short",
                "csrf_token": "registration-token",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIsNone(db_helper.get_user_by_username("newuser"))


if __name__ == "__main__":
    unittest.main()
