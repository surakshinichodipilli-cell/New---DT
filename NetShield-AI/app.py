import csv
import errno
import io
import ipaddress
import os
import re
import secrets
import socket
import threading
import time
from datetime import date, datetime
from functools import wraps

from dotenv import load_dotenv

load_dotenv()

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

from database.db_helper import (
    add_alert,
    delete_alert,
    delete_url_scan_history,
    ensure_db_exists,
    get_activity_for_user,
    get_dashboard_stats,
    get_dashboard_events,
    get_device_inventory,
    get_filtered_alerts,
    get_network_history_for_user,
    get_trusted_devices,
    get_url_history_for_user,
    get_url_scan_history,
    get_user_by_email,
    get_user_by_id,
    get_user_by_username,
    get_user_by_username_or_email,
    record_discovered_device,
    register_user,
    remove_trusted_device,
    save_network_scan,
    save_url_scan,
    trust_device,
    update_alert_status,
    update_password,
    update_user_settings,
)
from security.network_monitor import scan_network
from security.url_scanner import analyze_url

app = Flask(__name__)
IS_PRODUCTION = (
    os.getenv("APP_ENV", "development").strip().lower() == "production"
    or os.getenv("RENDER", "").strip().lower() == "true"
)
if IS_PRODUCTION and not os.getenv("DATABASE_URL", "").strip():
    raise RuntimeError("Set DATABASE_URL to a persistent PostgreSQL database in production.")
configured_secret = os.getenv("SECRET_KEY")
if not configured_secret or configured_secret.startswith("replace-with-"):
    if IS_PRODUCTION:
        raise RuntimeError("Set a strong SECRET_KEY before starting the production application.")
    app.logger.warning("SECRET_KEY is unset or still a placeholder; using an ephemeral key for this run.")
    configured_secret = secrets.token_urlsafe(48)
app.config["SECRET_KEY"] = configured_secret
app.config["IS_PRODUCTION"] = IS_PRODUCTION
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    IS_PRODUCTION or os.getenv("SESSION_COOKIE_SECURE", "").lower() == "true"
)
if IS_PRODUCTION:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
_rate_limit_lock = threading.Lock()
_rate_limit_events = {}


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id or not get_user_by_id(user_id):
            if request.path.startswith("/api/") or request.is_json:
                return jsonify({"success": False, "message": "Authentication required."}), 401
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped


def rate_limit(max_calls, window_seconds):
    def decorate(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if request.method != "POST":
                return view_func(*args, **kwargs)
            identity = str(session.get("user_id") or request.remote_addr or "unknown")
            key = (view_func.__name__, identity)
            now = time.monotonic()
            with _rate_limit_lock:
                timestamps = [
                    stamp for stamp in _rate_limit_events.get(key, [])
                    if now - stamp < window_seconds
                ]
                if len(timestamps) >= max_calls:
                    _rate_limit_events[key] = timestamps
                    return jsonify({
                        "success": False,
                        "message": "Too many requests. Please wait before trying again.",
                    }), 429
                timestamps.append(now)
                _rate_limit_events[key] = timestamps
            return view_func(*args, **kwargs)
        return wrapped
    return decorate


@app.context_processor
def inject_current_user():
    token = session.get("csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    user = get_user_by_id(session["user_id"]) if session.get("user_id") else None
    return {
        "current_user": user,
        "csrf_token": token,
        "now": datetime.now(),
        "cloud_deployment": app.config["IS_PRODUCTION"],
    }


@app.before_request
def check_csrf_token():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    expected = session.get("csrf_token")
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    if expected and supplied and secrets.compare_digest(expected, supplied):
        return None
    if request.path.startswith("/api/") or request.is_json:
        return jsonify({"success": False, "message": "Invalid or missing CSRF token."}), 400
    flash("Your session token is missing or expired. Please retry.", "danger")
    return redirect(url_for("landing"))


@app.after_request
def set_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:")
    if app.config["IS_PRODUCTION"]:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return response


def _request_data():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None
    return data


def _scan_url_for_user(raw_url, user_id):
    result = analyze_url(raw_url)
    save_url_scan(
        user_id,
        result["url"],
        result["risk_score"],
        result["risk_level"],
        result["detected_indicators"],
    )
    if result["risk_score"] >= 71:
        add_alert(
            user_id,
            "High Risk URL Detected",
            "High",
            f"The submitted URL scored {result['risk_score']} and was classified as high risk.",
            recommended_action="Do not open the link; verify its source and destination through a trusted channel.",
        )
    elif result["risk_score"] >= 31:
        add_alert(
            user_id,
            "Suspicious URL Pattern Detected",
            "Medium",
            "The submitted URL showed risk indicators and should be verified before use.",
            recommended_action="Confirm the domain and request with the organization using a known contact method.",
        )
    return result


def _validate_date_filter(value, name):
    if not value:
        return None
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError(f"{name} must use YYYY-MM-DD format.")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{name} must use YYYY-MM-DD format.") from exc


def _csv_cell(value):
    text = "" if value is None else str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def _csv_report_response(url_rows, network_rows):
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["Record Type", "Value", "Risk Score", "Risk Level", "Mode", "Date/Time"])
    for record in url_rows:
        writer.writerow([
            "URL scan", _csv_cell(record["url"]), record["risk_score"],
            record["risk_level"], "Rule-based text analysis", record["created_at"],
        ])
    for record in network_rows:
        writer.writerow([
            "Network scan", f'{record["total_devices"]} devices',
            record["risk_score"], record["risk_level"], record.get("mode", "live"),
            record["created_at"],
        ])
    return app.response_class(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=netshield-report.csv"},
    )


@app.route("/")
def landing():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
@rate_limit(10, 60)
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("login.html"), 400

        user = get_user_by_username_or_email(username)
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Login successful.", "success")
            next_path = request.args.get("next")
            if next_path not in {
                url_for("dashboard"), url_for("home"),
                url_for("scan_url"), url_for("network_scan"),
            }:
                next_path = url_for("dashboard")
            return redirect(next_path)

        flash("Invalid username or password. Please try again.", "danger")
        return render_template("login.html"), 401
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
@rate_limit(5, 60)
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        if not all([full_name, email, username, password, confirm_password]):
            flash("Please complete all fields.", "danger")
            return render_template("register.html"), 400
        if len(full_name) > 120 or len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Please enter a valid name and email address.", "danger")
            return render_template("register.html"), 400
        if not re.fullmatch(r"[a-z0-9_.-]{3,32}", username):
            flash("Username must be 3-32 characters and contain only letters, numbers, dots, underscores, or hyphens.", "danger")
            return render_template("register.html"), 400
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html"), 400
        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return render_template("register.html"), 400
        if get_user_by_email(email):
            flash("An account with this email already exists.", "danger")
            return render_template("register.html"), 409
        if get_user_by_username(username):
            flash("This username is already taken.", "danger")
            return render_template("register.html"), 409

        register_user(full_name, email, username, generate_password_hash(password))
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/home")
@login_required
def home():
    return render_template("home.html", stats=get_dashboard_stats(session["user_id"]))


@app.route("/dashboard")
@login_required
def dashboard():
    user_id = session["user_id"]
    stats = get_dashboard_stats(user_id)
    return render_template(
        "dashboard.html",
        stats=stats,
        activity=get_activity_for_user(user_id),
        events=get_dashboard_events(user_id),
        network_mode=get_user_by_id(user_id)["network_mode"],
        dashboard_active_alerts=stats["active_alerts"],
    )


@app.route("/api/dashboard")
@login_required
def api_dashboard():
    user = get_user_by_id(session["user_id"])
    return jsonify({
        "success": True,
        "stats": get_dashboard_stats(session["user_id"]),
        "activity": get_activity_for_user(session["user_id"]),
        "events": get_dashboard_events(session["user_id"]),
        "network_mode": user["network_mode"],
    })


@app.route("/scan-url", methods=["GET", "POST"])
@app.route("/api/scan-url", methods=["POST"])
@login_required
@rate_limit(12, 60)
def scan_url():
    if request.method == "POST":
        data = _request_data() or {}
        raw_url = request.form.get("url") if request.form else data.get("url", "")
        try:
            result = _scan_url_for_user(raw_url, session["user_id"])
            return jsonify({"success": True, "result": result})
        except ValueError as exc:
            return jsonify({"success": False, "message": str(exc)}), 400
    return render_template("url_detection.html")


@app.route("/api/scan-history", methods=["GET", "DELETE"])
@login_required
def api_scan_history():
    if request.method == "DELETE":
        delete_url_scan_history(session["user_id"])
        return jsonify({"success": True, "message": "Your URL scan history was deleted."})
    records = get_url_scan_history(session["user_id"])
    for record in records:
        record["detected_indicators"] = [
            item for item in (record.get("indicators") or "").split(" | ") if item
        ]
    return jsonify({"success": True, "scans": records})


def _network_scan_for_user(data, user_id):
    user = get_user_by_id(user_id)
    mode = user["network_mode"]
    if app.config["IS_PRODUCTION"] and mode == "live":
        raise RuntimeError(
            "Cloud hosting cannot scan your personal Wi-Fi network. "
            "Live monitoring requires a separately configured authorized local agent; "
            "no local agent is configured."
        )
    result = scan_network(mode=mode, authorized=data.get("authorized") is True)
    new_devices = 0
    unknown_devices = 0
    for device in result["devices"]:
        is_new, classification = record_discovered_device(user_id, device, mode)
        if mode == "live":
            if classification == "NEW":
                new_devices += 1
            elif classification == "UNKNOWN":
                unknown_devices += 1
        device["is_new"] = is_new
        device["classification"] = classification
        device["status"] = classification

    score = min(100, new_devices * 12 + unknown_devices * 18) if mode == "live" else 0
    level = "HIGH RISK" if score >= 71 else "SUSPICIOUS" if score >= 31 else "SAFE"
    result.update({
        "new_devices": new_devices,
        "unknown_devices": unknown_devices,
        "known_devices": sum(1 for item in result["devices"] if item["classification"] == "TRUSTED"),
        "suspicious_devices": 0,
        "risk_score": score,
        "risk_level": level,
    })
    save_network_scan(
        user_id,
        result["total_devices"],
        new_devices,
        0,
        score,
        level,
        mode=mode,
    )
    if mode == "live" and new_devices:
        add_alert(
            user_id,
            "New Network Device Detected",
            "Medium",
            f"{new_devices} previously unseen device(s) were discovered on the authorized local network.",
            recommended_action="Check the device with its owner and add it to the trusted list only if recognized.",
        )
    return result


@app.route("/network-scan", methods=["GET", "POST"])
@app.route("/api/network/scan", methods=["POST"])
@login_required
@rate_limit(2, 60)
def network_scan():
    if request.method == "POST":
        data = _request_data()
        if data is None:
            return jsonify({"success": False, "message": "A JSON request body is required."}), 400
        if (
            app.config["IS_PRODUCTION"]
            and get_user_by_id(session["user_id"])["network_mode"] == "live"
        ):
            return jsonify({
                "success": False,
                "message": (
                    "Cloud hosting cannot scan your personal Wi-Fi network. "
                    "Live monitoring requires a separately configured authorized "
                    "local agent; no agent is configured."
                ),
            }), 503
        try:
            result = _network_scan_for_user(data, session["user_id"])
            return jsonify({"success": True, "result": result})
        except (ValueError, PermissionError, RuntimeError) as exc:
            return jsonify({"success": False, "message": str(exc)}), 400
    user = get_user_by_id(session["user_id"])
    return render_template(
        "wifi_detection.html",
        network_mode=user["network_mode"],
        cloud_deployment=app.config["IS_PRODUCTION"],
    )


@app.route("/devices")
@login_required
def devices():
    return render_template(
        "devices.html",
        devices=get_device_inventory(session["user_id"]),
        trusted_devices=get_trusted_devices(session["user_id"]),
        network_mode=get_user_by_id(session["user_id"])["network_mode"],
    )


@app.route("/api/devices")
@login_required
def api_devices():
    return jsonify({
        "success": True,
        "devices": get_device_inventory(session["user_id"]),
        "trusted_devices": get_trusted_devices(session["user_id"]),
    })


def _normalize_device_key(value):
    key = (value or "").strip().lower()
    if not key or len(key) > 64:
        raise ValueError("A valid device IP address or MAC address is required.")
    try:
        return str(ipaddress.ip_address(key))
    except ValueError:
        if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", key):
            return key
        raise ValueError("Device identifier must be an IP address or MAC address.")


@app.route("/api/devices/trust", methods=["POST", "DELETE"])
@login_required
def api_device_trust():
    data = _request_data() or {}
    try:
        device_key = _normalize_device_key(data.get("identifier"))
        if request.method == "DELETE":
            remove_trusted_device(session["user_id"], device_key)
            return jsonify({"success": True, "message": "Trusted device record removed."})
        label = (data.get("label") or "").strip()
        if not label or len(label) > 80:
            raise ValueError("A device name between 1 and 80 characters is required.")
        trust_device(session["user_id"], device_key, label)
        return jsonify({"success": True, "message": "Device marked as trusted."})
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400


@app.route("/alerts")
@login_required
def alerts():
    severity = request.args.get("severity") or None
    event_type = request.args.get("event_type") or None
    if severity and severity not in {"Low", "Medium", "High", "Critical"}:
        flash("Invalid severity filter.", "danger")
        severity = None
    if event_type and len(event_type) > 120:
        flash("Event type filter is too long.", "danger")
        event_type = None
    alert_list = get_filtered_alerts(session["user_id"], severity, event_type)
    selected_alert = next(
        (alert for alert in alert_list if str(alert["id"]) == request.args.get("view")),
        None,
    )
    return render_template(
        "alerts.html",
        alerts=alert_list,
        selected_alert=selected_alert,
        selected_severity=severity,
        selected_event_type=event_type,
    )


@app.route("/api/alerts")
@login_required
def api_alerts():
    severity = request.args.get("severity") or None
    event_type = request.args.get("event_type") or None
    allowed_severities = {"Low", "Medium", "High", "Critical"}
    if severity and severity not in allowed_severities:
        return jsonify({"success": False, "message": "Invalid severity filter."}), 400
    if event_type and len(event_type) > 120:
        return jsonify({"success": False, "message": "Event type filter is too long."}), 400
    return jsonify({
        "success": True,
        "alerts": get_filtered_alerts(session["user_id"], severity, event_type),
    })


@app.route("/api/alerts/resolve", methods=["POST"])
@login_required
def api_resolve_alert():
    data = _request_data() or {}
    try:
        alert_id = int(data.get("alert_id"))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "A valid alert_id is required."}), 400
    if not update_alert_status(alert_id, session["user_id"], "resolved"):
        return jsonify({"success": False, "message": "Alert not found."}), 404
    return jsonify({"success": True, "message": "Alert marked as resolved."})


@app.route("/alerts/<int:alert_id>/review", methods=["POST"])
@login_required
def mark_alert_reviewed(alert_id):
    if update_alert_status(alert_id, session["user_id"], "resolved"):
        flash("Alert marked as resolved.", "success")
    else:
        flash("Alert not found.", "danger")
    return redirect(url_for("alerts"))


@app.route("/alerts/<int:alert_id>/delete", methods=["POST"])
@login_required
def delete_alert_route(alert_id):
    if delete_alert(alert_id, session["user_id"]):
        flash("Alert deleted.", "success")
    else:
        flash("Alert not found.", "danger")
    return redirect(url_for("alerts"))


def _report_rows(user_id, start_day=None, end_day=None):
    url_rows = get_url_history_for_user(user_id)
    network_rows = get_network_history_for_user(user_id)
    if start_day:
        url_rows = [row for row in url_rows if str(row["created_at"])[:10] >= start_day.isoformat()]
        network_rows = [row for row in network_rows if str(row["created_at"])[:10] >= start_day.isoformat()]
    if end_day:
        url_rows = [row for row in url_rows if str(row["created_at"])[:10] <= end_day.isoformat()]
        network_rows = [row for row in network_rows if str(row["created_at"])[:10] <= end_day.isoformat()]
    return url_rows, network_rows


@app.route("/reports")
@login_required
def reports():
    try:
        start_day = _validate_date_filter(request.args.get("from"), "from")
        end_day = _validate_date_filter(request.args.get("to"), "to")
        if start_day and end_day and start_day > end_day:
            raise ValueError("'from' must be on or before 'to'.")
    except ValueError as exc:
        flash(str(exc), "danger")
        start_day = end_day = None
    user_id = session["user_id"]
    url_history, network_history = _report_rows(user_id, start_day, end_day)
    if request.args.get("download") == "csv":
        return _csv_report_response(url_history, network_history)
    return render_template(
        "reports.html",
        url_history=url_history,
        network_history=network_history,
        date_from=start_day.isoformat() if start_day else "",
        date_to=end_day.isoformat() if end_day else "",
    )


@app.route("/api/reports")
@login_required
def api_reports():
    try:
        start_day = _validate_date_filter(request.args.get("from"), "from")
        end_day = _validate_date_filter(request.args.get("to"), "to")
        if start_day and end_day and start_day > end_day:
            raise ValueError("'from' must be on or before 'to'.")
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400
    urls, networks = _report_rows(session["user_id"], start_day, end_day)
    if request.args.get("format") == "csv":
        return _csv_report_response(urls, networks)
    return jsonify({"success": True, "url_scans": urls, "network_scans": networks})


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    user_id = session["user_id"]
    user = get_user_by_id(user_id)
    if request.method == "POST":
        action = request.form.get("action")
        if action == "profile":
            full_name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip().lower()
            if not full_name or len(full_name) > 120 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                flash("Enter a valid name and email address.", "danger")
                return render_template("settings.html", user=user), 400
            existing = get_user_by_email(email)
            if existing and existing["id"] != user_id:
                flash("This email is already registered.", "danger")
                return render_template("settings.html", user=user), 409
            update_user_settings(user_id, full_name=full_name, email=email)
            flash("Profile updated successfully.", "success")
        elif action == "password":
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            if not check_password_hash(user["password_hash"], current_password):
                flash("Current password is incorrect.", "danger")
                return render_template("settings.html", user=user), 400
            if len(new_password) < 8:
                flash("New password must be at least 8 characters long.", "danger")
                return render_template("settings.html", user=user), 400
            update_password(user_id, generate_password_hash(new_password))
            flash("Password changed successfully.", "success")
        elif action == "preferences":
            network_mode = request.form.get("network_mode", "demo")
            if network_mode not in {"demo", "live"}:
                flash("One or more preference values are invalid.", "danger")
                return render_template("settings.html", user=user), 400
            update_user_settings(user_id, network_mode=network_mode)
            flash("Preferences saved successfully.", "success")
        return redirect(url_for("settings"))
    return render_template("settings.html", user=user)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("landing"))


@app.errorhandler(404)
def page_not_found(_error):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "message": "Endpoint not found."}), 404
    return render_template("index.html"), 404


def _server_port_is_available(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((host, port))
    except OSError as exc:
        if exc.errno != errno.EADDRINUSE:
            raise
        app.logger.error(
            "Port %s is already in use. Close the other server using "
            "http://%s:%s or choose another port.",
            port,
            host,
            port,
        )
        return False
    return True


@app.errorhandler(500)
def internal_server_error(error):
    original_error = getattr(error, "original_exception", None)
    if original_error:
        app.logger.error(
            "Unhandled application error.",
            exc_info=(type(original_error), original_error, original_error.__traceback__),
        )
    else:
        app.logger.error("Unhandled internal server error: %s", error)
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "message": "An internal server error occurred."}), 500
    return app.response_class(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>Temporarily unavailable | NetShield AI</title>"
        "<h1>NetShield AI is temporarily unavailable.</h1>"
        "<p>Please try again later.</p></html>",
        status=500,
        mimetype="text/html",
    )


ensure_db_exists()


if __name__ == "__main__":
    default_host = "0.0.0.0" if IS_PRODUCTION else "127.0.0.1"
    server_host = os.getenv("HOST", default_host)
    try:
        server_port = int(os.getenv("PORT", "5000"))
    except ValueError as exc:
        raise SystemExit("PORT must be a whole number between 1 and 65535.") from exc

    if not 1 <= server_port <= 65535:
        raise SystemExit("PORT must be a whole number between 1 and 65535.")

    if not _server_port_is_available(server_host, server_port):
        raise SystemExit(1)

    print(f"Starting NetShield AI at http://{server_host}:{server_port}")
    try:
        app.run(
            debug=not IS_PRODUCTION and os.getenv("FLASK_DEBUG", "").lower() == "true",
            host=server_host,
            port=server_port,
            use_reloader=False,
        )
    except OSError as exc:
        app.logger.error("Could not start NetShield AI: %s", exc)
        raise SystemExit(1) from exc
