# 📘 Project Specification: Cross-Platform FRP Client Wrapper with Web GUI

## 🎯 Objective

Create a **cross-platform Python wrapper** for the frp client (`frpc`) that:

* Uses the same serving model Hugging Face uses for Gradio
  → **ASGI app powered by FastAPI + Uvicorn**
* Provides a **web-based GUI**
* Manages multiple `frpc` instances (via TOML configs)
* Automatically downloads the correct FRP binary for the user’s platform
* Runs locally on **port 2026**
* Launches via `run.sh`
* Provides ngrok-like monitoring for tunnels

---

# 🧭 Usecase

This platform is intended as **A unified, decentralized community-driven LMS** where multiple stakeholder groups can operate in parallel while remaining isolated and auditable.

Domains (UI tabs):

* Campus
* Family
* Corporate
* Community
* Government
* Non-Profit

`superadmin` remains global and is not restricted to a single domain.

## RBAC Implementation

Use **role-based access control** with session identity and owner scoping.

### Roles

* superadmin
* admin
* developer
* faculty
* staff
* teacher
* student
* parent
* collaborator
* user

### Enforcement Model

* Session cookie carries authenticated identity.
* API access requires authentication.
* Tunnel/instance operations are scoped to owner/session identity by default.
* Role grants are evaluated as: **role + resource + action + scope**.

Example scopes:

* `own` (self-owned resources)
* `domain` (selected governance domain)
* `global` (superadmin-level)

### Minimum Permission Matrix (MVP)

* `superadmin`: global user/role management, global tunnel visibility, full control.
* `admin`: domain administration, user onboarding, delegated management.
* `developer`: operational diagnostics/integration controls, no academic grading authority by default.
* `faculty`: curriculum and academic oversight in assigned programs.
* `staff`: operational modules (registrar/support/records) by assignment.
* `teacher`: class-level delivery, grading, attendance, learner communication.
* `student`: own coursework/submissions/progress only.
* `parent`: read-only linked student visibility + acknowledgments/consent flows.
* `collaborator`: limited project/course access by explicit assignment.
* `user`: baseline account with no privileged actions until assigned.

### Audit Requirements

Store append-only audit events for:

* login/logout
* access denied/allowed decisions
* tunnel create/start/stop/delete actions
* role/permission changes

---

# 🏗 Architecture Overview

```
run.sh
   ↓
Python launcher
   ↓
FastAPI (ASGI)
   ↓
frpc instance manager (subprocess controller)
   ↓
Platform-specific frpc binary
```

## 📁 Repo Layout (Current)

Python backend sources now live under `backend/src/gntl`.
`run.sh` launches the backend with `python -m gntl.main` using `backend/src` as `PYTHONPATH`.

```text
gntl/
├─ run.sh
├─ frontend/
│  └─ (SvelteKit dashboard shell)
├─ mobile/
├─ backend/
│  └─ src/
│     └─ gntl/
│        ├─ __init__.py
│        ├─ main.py
│        ├─ tunnel_manager.py
│        ├─ binary_manager.py
│        ├─ service_generator.py
│        ├─ ui.py
│        ├─ static/
│        └─ templates/
├─ bin/
├─ configs/
├─ services/
└─ requirements.txt
```

## 🧩 SvelteKit Frontend (New)

A new frontend shell is available under `frontend/` for faster UI iteration while keeping the current backend/mobile runtime stable.

```bash
cd frontend
npm install
npm run dev
```

Default dev URL: `http://127.0.0.1:5173` (proxied to backend API at `http://127.0.0.1:2026`).

## 🔐 Environment Files

- Use `.env.example` as the template.
- Create your local `.env` for machine-specific values.
- `.env` is gitignored; `.env.example` is committed.

Key variables:

- `GNTL_HTTP_PORT`, `GNTL_HTTPS_PORT`
- `GNTL_INSTANCE_HTTP_PORT`, `GNTL_INSTANCE_HTTPS_PORT`
- `GNTL_ENABLE_HTTP_ON_CREATE`
- `GNTL_MOBILE_USE_CADDY`, `GNTL_MOBILE_PHP_PORT`
- `GNTL_MOBILE_REQUIRE_AUTH` (default `1`; set to `0` to bypass mobile login/auth requirement)
- `GNTL_PHP_BIN` (optional override for mobile shells, e.g. `php84`)
- `GNTL_FRP_VERSION` (FRP version used by both `run.sh` and the backend downloader, default `0.67.0`)
- `GNTL_AUTO_OPEN_APP` (default `1`; set to `0` to disable auto-opening `127.0.0.1:2026` after successful startup)
- `GNTL_ENABLE_TUNNELS` (default `1`; set to `0` to skip frpc tunnel preparation on desktop hosts)
- `GNTL_NODE_MIN_MAJOR` / `GNTL_NODE_INSTALL_MAJOR` (default `18` / `20`; minimum accepted and installed Node.js major)
- `GNTL_NODE_LOCAL_INSTALL` (default `0`; set to `1` — same as `--local-node` — to install Node into `bin/node` instead of using system packages)
- `GNTL_UBUNTU_BOOTSTRAP` (default `0`; set to `1` for the same effect as `./run.sh ubuntu`)

On startup, `run.sh` auto-creates `.env` (if missing) and ensures `GNTL_MOBILE_USE_CADDY=1` and `GNTL_MOBILE_REQUIRE_AUTH=1` are present, then loads `.env` values for runtime config.

`run.sh` ensures an architecture-matched `frpc` binary with the configured `GNTL_FRP_VERSION` before instances are autostarted, on both mobile and desktop hosts:

- accepts existing/system/package-manager `frpc` only when the version matches `GNTL_FRP_VERSION`
- otherwise downloads the matching GitHub release for the detected CPU arch

## 🐧 Ubuntu / Debian Desktop Mode

```bash
./run.sh ubuntu
```

Installs host prerequisites, then continues into the normal desktop run:

- apt packages: `ca-certificates curl wget tar gzip openssl python3 python3-venv python3-pip sqlite3`
- Node.js LTS from NodeSource (`GNTL_NODE_INSTALL_MAJOR`, default `20`), falling back to the distro `nodejs`/`npm` packages
- the pinned `frpc` client at `bin/frpc`

Notes:

- `sudo` prompts stay visible; the script no longer silences the package manager, so a password request cannot look like a hang.
- Node installed via `nvm`/`fnm` is detected and used even when it is not on `PATH` for non-login shells. Node older than `GNTL_NODE_MIN_MAJOR` (default `18`) is upgraded rather than accepted.
- `nodejs` and `npm` are never requested from apt in the same transaction: NodeSource `nodejs` bundles npm and declares `Conflicts: npm`, which makes apt reject the whole install ("held broken packages"). The distro `npm` package is installed only when a distro `nodejs` landed without it.
- A failed `python3 -m venv` (Debian/Ubuntu ship `ensurepip` separately) is recovered automatically: the versioned `pythonX.Y-venv` package is installed, and without root the venv is created with `--without-pip` and pip is bootstrapped into it. The partial `.venv` directory a failed attempt leaves behind is removed rather than reused — reusing it silently fell through to the system Python.

### Managed servers (Virtualmin, cPanel, shared hosts)

```bash
./run.sh --local-node
```

Downloads the official Node.js build into `bin/node` and puts it on `PATH` for the run — no root, no apt, and the host's system packages are left alone. This is also the automatic fallback whenever the package manager cannot produce a usable Node (broken/held packages, `nodejs`/`npm` conflicts, or a distro Node that is too old), and when the script is running without root or `sudo`. A system Node still wins whenever it satisfies `GNTL_NODE_MIN_MAJOR`; `bin/node` is only used when it cannot.
- Plain `./run.sh` on a desktop host also prepares tunnels: it guarantees `bin/frpc` exists before the backend starts, and the backend then auto-starts every enabled instance from `configs/instances_state.json`. Reading that state file no longer requires `php-cli` — `python3` is used when PHP is absent, which is the norm on Ubuntu.
- Use `./run.sh --no-tunnels` (or `GNTL_ENABLE_TUNNELS=0`) to skip tunnel preparation for a run.
- `ubuntu` combines with the other commands, e.g. `./run.sh ubuntu frontend-install`.

## 📱 Mobile Runtime (Android/iOS Shell)

`run.sh` now uses a platform split:

- Desktop/server shells (Linux/macOS/Windows): existing Python + FastAPI runtime.
- Mobile shells:
  - Android Termux → lightweight PHP + SQLite runtime (`mobile/`)
  - iOS iSH (Alpine shell) → lightweight PHP + SQLite runtime (`mobile/`)

Mobile mode is auto-detected in `run.sh` and avoids Python dependency by default.

### Mobile launch behavior

- Before starting runtime, `run.sh` now always runs frontend routines: dependency install (`npm install`), compile/type check (`npm run check`), and build (`npm run build`).
- On mobile shells, this same routine runs before the mobile PHP runtime starts, and the mobile UI is served from the built SvelteKit frontend (`frontend/build`).
- If Caddy is installed, `run.sh` starts:
  - PHP app on `127.0.0.1:2027`
  - Caddy reverse proxy on `127.0.0.1:2026`
- If Caddy is unavailable, it serves PHP directly on `127.0.0.1:2026`.

### Mobile app files

- `mobile/index.php` → auth + mobile API/session backend; serves SvelteKit dashboard when authenticated
- `mobile/router.php` → router for PHP built-in server + SvelteKit static asset passthrough

SQLite database path for mobile auth:

```
configs/webadmin_mobile.sqlite3
```

---

# 🧱 Core Requirements

## 1️⃣ Platform Detection & Binary Management

The wrapper must:

* Detect OS:

  * Linux
  * macOS (Intel & ARM)
  * Windows
* Detect architecture:

  * amd64
  * arm64

Use:

```python
import platform
platform.system()
platform.machine()
```

Then:

* Fetch correct binary from official FRP GitHub releases
* Extract it
* Store in:

  ```
  ./bin/frpc
  ```
* Ensure executable permission on Unix:

  ```
  chmod +x
  ```

If binary exists, skip download.

---

## 2️⃣ Instance Management System

Each FRPC instance:

* Has its own `.toml` config
* Runs as a separate subprocess
* Has its own status tracking

Design:

```python
class FrpcInstance:
    id: str
    config_path: str
    process: subprocess.Popen
    status: running/stopped/error
    logs: ring buffer
```

Manager:

```python
class FrpcManager:
    start_instance()
    stop_instance()
    restart_instance()
    list_instances()
    get_logs()
```

Subprocess should:

* Run non-blocking
* Capture stdout/stderr
* Stream logs to UI

---

## 3️⃣ GUI (Gradio-Based)

Mount Gradio inside FastAPI like HF does:

```python
app = FastAPI()
app = gr.mount_gradio_app(app, demo, path="/")
```

Launch via:

```python
uvicorn app:app --host 127.0.0.1 --port 2026
```

---

# 🖥 GUI Requirements

Web UI must include:

### Dashboard (ngrok-style)

For each instance show:

* Instance ID
* Remote address
* Local port
* Status (🟢 running / 🔴 stopped)
* Uptime
* Active connections (if available)
* Logs viewer (live scroll)

---

### Controls

Per instance:

* ▶ Start
* ⏹ Stop
* 🔁 Restart
* 🗑 Delete
* 📄 Edit TOML
* 📋 View Logs

---

### Create Instance

Form fields:

* Server address
* Server port
* Auth token (optional)
* Local port
* Remote port
* Protocol (tcp/http/https)

Generate TOML automatically.

---

# 🔐 Security Constraints

* Must bind only to:

  ```
  127.0.0.1:2026
  ```
* No external exposure by default
* Optional local Bearer token auth (future-ready)

---

# 📂 Project Structure

```
/frp-wrapper
│
├── run.sh
├── main.py
├── tunnel_manager.py
├── binary_manager.py
├── ui.py
├── /bin
├── /configs
└── /logs
```

---

# 🚀 run.sh Requirements

Must:

1. Create venv if not exists
2. Install dependencies
3. Launch server

Example behavior:

```bash
#!/usr/bin/env bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

### Optional TLS for Web Admin

The web admin can run with HTTPS using a certificate and key.

By default, `./run.sh` now auto-generates and reuses a local self-signed cert/key at:

```text
configs/tls/webadmin.crt
configs/tls/webadmin.key
```

So you can run:

```bash
./run.sh
```

and it will start on HTTPS automatically when `openssl` is available.

Environment variables:

```bash
export GNTL_TLS_CERT=/absolute/path/to/cert.pem
export GNTL_TLS_KEY=/absolute/path/to/key.pem
./run.sh
```

Or pass arguments directly:

```bash
./run.sh --tls-cert /absolute/path/to/cert.pem --tls-key /absolute/path/to/key.pem
```

When TLS is configured, access the dashboard at:

```text
https://127.0.0.1:2026
```

If TLS variables are not set, it continues to run as:

```text
http://127.0.0.1:2026
```

### Web Admin Password Lock

Web admin is now locked by default until you create a secure password.

- First access redirects to `/setup`.
- Password policy: minimum 12 characters, uppercase, lowercase, number, and symbol.
- Password hash is stored locally in SQLite at `configs/webadmin.sqlite3` (scrypt hash + random salt).
- After setup, unauthenticated requests are redirected to `/login` (or `401/403` for API calls).

Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`, with a 12-hour session TTL.

---

# 📡 Monitoring Requirements (ngrok-like)

For each instance, display:

* Config summary
* Running PID
* Real-time logs
* Public endpoint
* Error state
* Restart count

Logs must auto-refresh.

Use:

* Async background task
* WebSocket or polling

---

# ⚙ Dependency Requirements

Minimum:

```
fastapi
uvicorn
gradio
httpx
psutil
toml
```

---

# 🧠 Operational Flow

1. User runs:

   ```
   ./run.sh
   ```
2. Browser opens:

   ```
   http://localhost:2026
   ```
3. User:

   * Creates instance
   * Config saved to `/configs`
   * Manager starts subprocess
4. Dashboard updates live
5. Logs streamed
6. User can manage multiple tunnels

---

# 📌 Cross-Platform Handling

Windows:

* Use `.exe`
* Use `creationflags=subprocess.CREATE_NEW_PROCESS_GROUP`

Linux/macOS:

* Use `chmod`
* Handle SIGTERM cleanly

---

# 🔄 Process Handling Rules

When stopping:

```python
process.terminate()
wait 5 seconds
if still alive:
    process.kill()
```

Must avoid zombie processes.

---

# 📈 Optional Enhancements (Future)

* Auto-start on boot
* Config import/export
* JSON API endpoint

---

## 🔁 Instance Auto-Start Artifacts

When a new instance is created, the app now generates reboot-persistence artifacts in `services/`:

* `services/systemd/` for Linux user services
* `services/launchd/` for macOS LaunchAgents
* `services/windows/` for Windows Scheduled Tasks

The API attempts a best-effort install on the current platform immediately after creation. If automatic install fails, instance creation still succeeds and install commands are returned in the API response.

### Platform Coverage

* Linux: systemd user services
* macOS: launchd LaunchAgents
* Windows: Scheduled Tasks
* Termux (Android): `.termux/boot` script generation + installer
* Android (non-Termux): returns guidance to use Termux + Termux:Boot
* iOS: service auto-install is not supported due platform restrictions

### Restart Persistence

Created instances are now reloaded from `configs/*.toml` on app startup, and metadata is persisted in `configs/instances_state.json` so controls and instance rows remain available after restarts.
* Docker packaging
* System tray integration
* Resource usage graphs

---

# 🧪 Acceptance Criteria

✅ Downloads correct FRP binary
✅ Runs on Windows/macOS/Linux
✅ Runs at localhost:2026
✅ Supports multiple concurrent instances
✅ GUI dashboard live updates
✅ Logs visible per instance
✅ Clean shutdown
✅ No external exposure

---

# 📣 Final Instruction to Agent

> Implement a cross-platform Python wrapper for FRP client that uses FastAPI + Uvicorn + Gradio (HF-style architecture).
> It must download correct binaries automatically, manage multiple frpc TOML-based instances, provide real-time monitoring via web GUI, and run locally on port 2026 when launched via run.sh.
