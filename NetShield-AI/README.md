# NetShield AI

NetShield AI is a local Flask and SQLite project for transparent URL text analysis, on-demand discovery of an authorized local network, device trust records, alerts, and reporting.

## Features

- Account registration and login using Werkzeug password hashing.
- URL scanning with a transparent rule-based baseline. Submitted URLs are not visited, resolved, or fetched. There is no trained ML model or labeled training dataset in this project.
- Persisted per-account URL scan history with a delete-history action.
- Dashboard statistics and charts derived from saved database records.
- Account-scoped URL, network, and alert activity on the dashboard, refreshed automatically while it is open.
- Per-account Demo or Live network mode. Demo output is simulated and labeled; Live mode attempts ARP discovery only after explicit authorization.
- Discovered-device inventory with first-seen/last-seen values and trusted-device records.
- Persisted alerts with severity/event filters and resolve actions.
- Date-filtered CSV reports built from saved URL and network scans.
- JSON endpoints under `/api/` for the dashboard, scanners, devices, alerts, history, and reports.

## Run on Windows

### Start and stop the website

Whenever you close the server window, close VS Code, or shut down your computer, the local website stops. Start it again whenever you want to use it:

1. Double-click `start_netshield.bat` in the `NetShield-AI` project folder.
2. Leave the opened terminal window running. It checks the project's virtual environment and required packages, then starts Flask at <http://127.0.0.1:5000>.
3. Open Chrome and visit <http://127.0.0.1:5000>.
4. To stop the server, press `Ctrl+C` in the terminal window. The window stays open so you can read any error messages.

If port 5000 is already being used, close the other server window and run `start_netshield.bat` again. The existing database at `database/netshield.db` is reused when the app starts; starting the app does not reset user accounts or scan history.

You can also start the application from the project folder with `python app.py` (or `.\.venv\Scripts\python.exe app.py`). The server is a local program and does not remain accessible after its process stops or your computer shuts down.

Open PowerShell in the project folder (`NetShield-AI`) and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Create a local environment file only if one does not already exist. Do not replace an existing `.env` file:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

Edit `.env` and replace `SECRET_KEY` with a random value. Generate one with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

The database schema is initialized automatically when the application starts. Run the tests and then start the server:

```powershell
python -m unittest discover -s tests -v
python app.py
```

Open <http://127.0.0.1:5000>, create an account, and sign in. The default network mode for a new account is **Demo**; this lets you demonstrate the UI without special hardware or elevated permissions.

To stop the local server, press `Ctrl+C` in PowerShell.

## Deploy publicly on Render

The Render configuration in `render.yaml` creates a Python web service and a persistent PostgreSQL database. The web service runs Gunicorn on Render's assigned `PORT`, bound to `0.0.0.0`. Your laptop and VS Code do not need to stay on after the cloud deployment succeeds. This repository is prepared for deployment, but the service and public URL are not created until you complete these steps in your own GitHub and Render accounts.

### 1. Back up your local database

Before migrating, copy `database/netshield.db` somewhere safe on your computer. The migration command only reads this SQLite file and refuses to overwrite a PostgreSQL database that already contains records.

### 2. Create a GitHub repository

1. Install and open GitHub Desktop, then sign in to your GitHub account.
2. Choose **File → Add Local Repository** and select the existing `NetShield-AI` project folder. If it is not already a Git repository, choose GitHub Desktop's option to create a repository in this existing folder.
3. Confirm that `.env`, `.venv`, and `database/netshield.db` are excluded by `.gitignore`. Do not upload `.env`, database credentials, or the database file.
4. Commit the project files and choose **Publish repository**. A private repository is a sensible default.

The existing application files and features remain in this repository; do not make a replacement static site.

### 3. Connect the repository to Render

1. Create or sign in to your account at [Render](https://render.com/).
2. In the Render dashboard, choose **New → Blueprint** and connect the GitHub repository you published.
3. Review the Blueprint services before applying it. `render.yaml` defines the web service and a persistent **Basic-256mb PostgreSQL** database. Check Render's current prices and plan terms before confirming; the database is a paid persistent service.
4. Confirm the Blueprint. Render builds the repository and assigns the web service a URL such as `https://netshield-ai.onrender.com`. The exact URL is assigned by Render and may differ if that name is unavailable.

### 4. Check build, start, and environment settings

The Blueprint preconfigures these values:

- **Build command:** `pip install -r requirements.txt`
- **Start command:** `gunicorn --workers 1 --threads 4 --bind 0.0.0.0:$PORT app:app`
- `APP_ENV=production`
- `SECRET_KEY`: generated by Render and kept outside the source code.
- `DATABASE_URL`: the PostgreSQL connection string supplied by the Render database.
- `SESSION_COOKIE_SECURE=true`

In Render, open the web service's **Environment** page and confirm that the variables are present. Do not copy passwords or connection strings into GitHub. Production startup fails rather than falling back to an insecure placeholder secret or temporary SQLite storage if required settings are missing. Flask debug mode is disabled in production.

### 5. Migrate existing SQLite accounts and history

PostgreSQL is a new, separate database: deploying the app does **not** copy records from your laptop automatically. Migrate before registering users or creating records on the new service. The migration copies users and their existing password hashes, URL scans, device records, network scans, alerts, and trusted devices. It leaves the SQLite source untouched and refuses to run over existing destination records.

1. In Render, open the PostgreSQL database and copy its **External Database URL**. If Render asks, allow your current IP for this migration; do not change the service's internal `DATABASE_URL`.
2. Open PowerShell in the existing `NetShield-AI` folder and run:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   $env:DATABASE_URL = Read-Host "Paste the Render PostgreSQL External Database URL"
   $env:SQLITE_DATABASE_PATH = "database\netshield.db"
   python -m database.migrate_sqlite_to_postgres
   Remove-Item Env:DATABASE_URL
   Remove-Item Env:SQLITE_DATABASE_PATH
   ```

3. Confirm that the script reports copied row counts. If it says a destination table is not empty, stop and investigate before retrying; the script intentionally does not delete or replace destination data.
4. When migration finishes, the web service continues to use the database's internal connection string from Render.

Skip this step only if you do not need the data from your existing SQLite database. Keep your backup until you have confirmed that you can sign in and see your history on the public service.

### 6. Deploy and test the public URL

1. Wait until Render reports that the latest deployment succeeded. Read the build and deploy logs if it fails; do not treat a configured Blueprint as a completed deployment.
2. Open the public HTTPS URL shown on the Render service page. Confirm the landing page loads, register or sign in, and check the dashboard, URL Detection, Alerts, Reports, and Settings.
3. Test the public HTTPS URL from a different browser and a phone using mobile data or another Wi-Fi network. Sign in with an account you control; never share your password.
4. After a successful SQLite migration, sign in with an existing account and confirm that its URL and network history is present.

Only Render can confirm that a deployment succeeded and provide its actual public URL. A free web-service plan may sleep when idle and take longer to answer the first request; the separate PostgreSQL database configured here is persistent.

### Cloud network-monitoring limitation

A Render service cannot scan the private Wi-Fi network attached to your laptop or phone. The cloud deployment rejects live scans and labels them as requiring a local monitoring agent; **that agent and cloud bridge are not implemented yet**. Demo results remain simulated and labeled. Do not change the cloud app to scan the Render host as a substitute.

A future agent should run only on a computer that the network owner authorizes, collect a minimal allowlisted set of device details, and send reports to the service over HTTPS using a per-installation revocable credential. It should not accept scan commands from the public website or perform scans without local authorization. Until such an agent and its authenticated reporting API are implemented and reviewed, use Demo mode in the cloud. The existing Live scanner is for authorized local development only.

## Demo and Live network modes

- **Demo:** Uses a fixed set of clearly labeled simulated devices. These samples are not evidence of real devices on the network.
- **Live (local development only):** On the local app, select this under **Settings**, then open **Wi-Fi Detection** and confirm that you own or are authorized to scan the connected network before starting a scan. Discovery derives the active interface address and scans only its private IPv4 `/24` subnet. It does not attempt access, interception, exploitation, password cracking, or router configuration. Live scanning is disabled on cloud deployments until a local agent is implemented.
- Live discovery requires Scapy and can require Npcap and administrator privileges on Windows. Unsupported interfaces, permissions, or dependencies are reported as errors; the app does not silently substitute demo devices.
- Scans are manual. There is no background or continuous monitoring.
- Devices first observed by the application are marked new/unverified. Mark a device trusted only after you recognize it; hostname information is best-effort and is not proof of ownership.

## URL risk estimates

The scanner examines URL text only (scheme, hostname, length, patterns, and related indicators). It returns an estimate, reasons, and recommendations. A low score does not prove that a site is safe, and a high score does not prove that it is malicious. No external reputation API is configured and URLs are never fetched, which avoids arbitrary-URL server-side requests.

## Configuration

`.env.example` documents supported environment values:

- `SECRET_KEY`: required for stable sessions; set a long random value.
- `DATABASE_PATH`: SQLite file path; defaults to `database/netshield.db`.
- `HOST` and `PORT`: local bind address and port; defaults to `127.0.0.1:5000`.
- `FLASK_DEBUG`: enable Flask debug mode only for local development.
- `SESSION_COOKIE_SECURE`: set to `true` only when serving over HTTPS.

The app does not enable cross-origin access. Mutating form and JSON requests require a session CSRF token. The simple in-process rate limiter is suitable only for a local demonstration; use a production rate-limiting service and deployment configuration before exposing this app beyond localhost.

Chart.js is loaded from jsDelivr for dashboard charts, so charts require an internet connection. The scanning and database features themselves are local. Sign-in opens the account dashboard; a dashboard without saved scans shows an initial-baseline message rather than inventing a security score. Network results in Demo mode are labeled as simulated.

## Tests

The standard-library `unittest` suite covers URL parsing/classification, CSRF behavior, authenticated API flows, database persistence, demo labeling, and account-scoped alerts/reports. It uses a temporary SQLite database and does not perform a live network scan.

## Project layout

- `app.py` — Flask pages, REST endpoints, authentication, and request protections.
- `database/db_helper.py` — SQLite/PostgreSQL schema and user-scoped data access.
- `database/migrate_sqlite_to_postgres.py` — non-destructive copy of existing local records to an empty PostgreSQL database.
- `render.yaml` and `Procfile` — Render service, persistent database, and Gunicorn startup configuration.
- `security/url_scanner.py` — URL normalization and transparent rule-based analysis.
- `security/network_monitor.py` — labeled demo data and explicit authorized local discovery.
- `templates/` — dashboard, scanner, device, alerts, settings, and report pages.
- `static/` — responsive styling and browser interactions.
- `tests/` — focused unit and API tests.

## Limitations

This is an educational local project, not a production security product. It has no continuous monitoring, external threat-intelligence feed, trained classifier, device blocking, or guarantee of safety. The application trusts its local SQLite file and is intended for a single-process local demonstration.
