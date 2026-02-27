# Secure, User-Consented Cross-Platform Autostart Design

## 1) Goals and Non-Goals

### Goals
- Start `frpc` automatically only for user-enabled, existing client configs.
- Never start removed or disabled configs.
- Persist client lifecycle state (`active`, `inactive`, `deleted`) transparently and reversibly.
- Keep all control local to the user (no remote credential generation, no hidden control paths).
- Use SQLite as portable local datastore across desktop and Android.
- Use platform-native autostart mechanisms:
  - Linux: `systemd --user`
  - macOS: `launchd` (LaunchAgents)
  - Windows: Task Scheduler
  - Android: Foreground Service + WorkManager (+ optional boot receiver)

### Non-Goals
- iOS background daemonization (restricted by platform policy).
- Cloud-hosted identity providers or remote credential escrow.

---

## 2) High-Level Architecture

### Components
1. **Control Plane API (local-only)**
   - FastAPI bound to `127.0.0.1` by default.
   - Exposes CRUD for clients/configs, enable/disable toggles, and start/stop actions.

2. **State Store (SQLite)**
   - Single source of truth for config metadata, status, auth records, lockouts, and audit events.

3. **Runtime Supervisor**
   - Starts/stops `frpc` child processes.
   - Performs preflight checks before launch:
     - config exists
     - config not deleted
     - config enabled
     - binary exists and is executable

4. **Autostart Integrator**
   - Installs/updates/removes platform-specific startup units.
   - Startup entrypoint always calls the same reconciler:
     - Read desired state from SQLite.
     - Start exactly the enabled+existing set.
     - Stop orphaned/disabled/deleted set.

5. **Security Layer**
   - Local admin password setup during install/bootstrap.
   - Password hashing via Argon2id (preferred), bcrypt/scrypt fallback.
   - Rate limiting + temporary lockouts + anomaly scoring.

### Boot Reconciliation Contract
At app launch (manual or autostart), run:
1. Acquire exclusive startup lock.
2. Query desired clients (`enabled=1 AND deleted_at IS NULL`).
3. Validate config file existence and checksum/version metadata.
4. Start missing desired processes.
5. Stop running processes that are now undesired.
6. Record results in `audit_events` and update `clients.runtime_state`.

---

## 3) SQLite Data Model

Use WAL mode and foreign keys:
- `PRAGMA journal_mode=WAL;`
- `PRAGMA foreign_keys=ON;`

### `admin_user`
- `id INTEGER PRIMARY KEY CHECK (id=1)`
- `password_hash TEXT NOT NULL`
- `hash_algo TEXT NOT NULL` (`argon2id`, `bcrypt`, `scrypt`)
- `created_at TEXT NOT NULL`
- `updated_at TEXT NOT NULL`
- `failed_attempts INTEGER NOT NULL DEFAULT 0`
- `locked_until TEXT NULL`
- `last_login_at TEXT NULL`

### `clients`
- `id TEXT PRIMARY KEY` (stable UUID/slug)
- `display_name TEXT NOT NULL`
- `config_path TEXT NOT NULL UNIQUE`
- `config_sha256 TEXT NULL`
- `enabled INTEGER NOT NULL DEFAULT 1`
- `state TEXT NOT NULL` (`active`, `inactive`, `deleted`)
- `runtime_state TEXT NOT NULL DEFAULT 'stopped'` (`running`, `stopped`, `error`)
- `last_exit_code INTEGER NULL`
- `created_at TEXT NOT NULL`
- `updated_at TEXT NOT NULL`
- `deleted_at TEXT NULL`

### `client_metadata`
- `client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE`
- `key TEXT NOT NULL`
- `value TEXT NOT NULL`
- `PRIMARY KEY (client_id, key)`

### `service_bindings`
- `client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE`
- `platform TEXT NOT NULL` (`linux`, `macos`, `windows`, `android`)
- `binding_type TEXT NOT NULL` (`systemd`, `launchd`, `schtasks`, `workmanager`, `foreground_service`)
- `binding_name TEXT NOT NULL`
- `install_path TEXT NULL`
- `is_installed INTEGER NOT NULL DEFAULT 0`
- `last_checked_at TEXT NULL`
- `last_error TEXT NULL`
- `PRIMARY KEY (client_id, platform, binding_type)`

### `auth_attempts`
- `id INTEGER PRIMARY KEY AUTOINCREMENT`
- `ts TEXT NOT NULL`
- `source TEXT NOT NULL` (loopback IP / app session id)
- `outcome TEXT NOT NULL` (`success`, `failure`, `blocked`)
- `reason TEXT NULL`

### `audit_events`
- `id INTEGER PRIMARY KEY AUTOINCREMENT`
- `ts TEXT NOT NULL`
- `actor TEXT NOT NULL` (`admin`, `system`, `installer`)
- `event_type TEXT NOT NULL`
- `target_id TEXT NULL`
- `payload_json TEXT NULL`

### `anomaly_signals`
- `id INTEGER PRIMARY KEY AUTOINCREMENT`
- `ts TEXT NOT NULL`
- `signal_type TEXT NOT NULL` (e.g., `rapid_failures`, `config_tamper`)
- `severity INTEGER NOT NULL` (1-5)
- `details TEXT NULL`
- `resolved INTEGER NOT NULL DEFAULT 0`

---

## 4) State Machine and Reversibility

### Allowed transitions
- `inactive -> active` (enable)
- `active -> inactive` (disable)
- `active|inactive -> deleted` (soft delete)
- `deleted -> inactive` (restore)

### Behavioral rules
- `enabled=1` requires `state IN ('active','inactive')` and `deleted_at IS NULL`.
- `state='deleted'` forces `enabled=0`.
- Autostart reconciler starts only rows where `enabled=1 AND state!='deleted'` and file exists.
- If file missing, mark runtime error + emit `config_missing` audit event; do not launch.

### User transparency
- No hard delete by default.
- UI exposes restore action for soft-deleted records.
- “Purge permanently” is explicit and logs `audit_events`.

---

## 5) Installer and Password Bootstrap

### Setup flow (required)
1. Installer starts local setup wizard.
2. User must create admin password before service install completes.
3. Password policy (example): min 12 chars, deny common leaked passwords.
4. Hash with Argon2id (memory-hard), store only hash + algorithm + params.
5. Write initial `admin_user` row, create bootstrap audit event.

### Hashing baseline
- Preferred: Argon2id (e.g., memory >= 64MB, iterations >= 3, parallelism tuned to device).
- Fallback: bcrypt cost >= 12 or scrypt with strong N/r/p.
- Never store plaintext, reversible encryption, or shared default credentials.

---

## 6) Defensive Security Controls

### Rate limiting
- Sliding window per source and global:
  - e.g., max 5 failed attempts / 5 min per source.
  - max 30 failed attempts / 10 min global.

### Temporary lockout
- Escalating lockouts after threshold breaches:
  - 1st lockout: 5 min
  - 2nd: 15 min
  - 3rd+: 60 min

### Anomaly detection
Record and optionally alert on:
- Rapid failed auth bursts.
- Attempts during lockout windows.
- Repeated config checksum mismatches.
- Unexpected mass delete/disable actions.

### Access surface hardening
- Bind web API to loopback only by default.
- CSRF protection for browser-based local UI.
- SameSite cookies / secure session handling.
- No debug endpoints exposing secrets.
- No hidden fallback accounts or override tokens.

---

## 7) Platform-Specific Autostart Approach

## 7.1 Linux (`systemd --user`)
- Create one template unit or per-client unit files under `~/.config/systemd/user/`.
- Unit executes manager bootstrap command (not direct raw `frpc`), so SQLite reconciliation is always applied.
- Enable with `systemctl --user enable <unit>`.
- Recommend optional linger (`loginctl enable-linger`) if start without active login is desired.

## 7.2 macOS (`launchd` LaunchAgents)
- Install plist in `~/Library/LaunchAgents/`.
- `RunAtLoad=true`, `KeepAlive=true`.
- Program launches manager bootstrap command.
- Keep stdout/stderr to user-accessible logs.

## 7.3 Windows (Task Scheduler)
- Register per-user tasks with triggers `AtLogOn` and optional `AtStartup`.
- Action runs manager bootstrap executable/script.
- Use least-privilege user context; avoid storing plaintext credentials in task definition.

## 7.4 Android (Policy-Compliant)

Use an Android-native wrapper app around the manager runtime or an embedded client runtime.

### Required mechanisms
1. **Foreground Service**
   - Persistent notification while `frpc` client(s) run.
   - Explicit start/stop from user actions in app.
   - Maintains long-running process compliantly.

2. **WorkManager**
   - Schedules periodic reconciliation (`enabled+existing` set).
   - Handles deferred restart/recovery in doze-friendly manner.

3. **BOOT_COMPLETED receiver (optional, user-consented)**
   - On reboot, enqueue WorkManager and/or start foreground service based on user toggle.
   - Respect Android 12+ background start restrictions by delegating to approved APIs.

4. **Storage**
   - Store SQLite DB in app-internal storage (`Context.getDatabasePath`).
   - Config files in app-private files dir or SAF-backed user-selected documents with persisted URI permissions.

5. **Security**
   - Local auth secret hash in SQLite; optional key material in Android Keystore for token/session encryption.
   - Do not expose manager endpoints externally unless user intentionally configures it.

### Immediate testability on Android
- Install debug build.
- Create admin password in first-run wizard.
- Register two configs, disable one.
- Start foreground service and verify only enabled existing config starts.
- Reboot device/emulator, confirm recovery behavior matches user opt-in.
- Delete config file, verify service skips launch and logs `config_missing` event.

---

## 8) Migration from Current JSON State

Current state file: `configs/instances_state.json`.

### One-time migration
1. Open/create SQLite DB.
2. Read JSON map entries and discover `configs/*.toml`.
3. Insert into `clients` with inferred `enabled=1`, `state='active'` unless metadata indicates otherwise.
4. Create `client_metadata` rows from prior metadata.
5. Mark missing config paths as `inactive` + runtime error note.
6. Backup JSON and switch manager reads/writes to SQLite only.

### Compatibility window
- Keep JSON export endpoint for user transparency.
- Do not treat JSON as source of truth after migration.

---

## 9) Implementation Plan (Incremental)

1. Add `state_store.py` with SQLite schema init + repository methods.
2. Replace `FrpcManager._load_state/_save_state` with SQLite-backed equivalents.
3. Add explicit `enable_instance`, `disable_instance`, `soft_delete_instance`, `restore_instance` APIs.
4. Add auth module:
   - setup wizard endpoint
   - Argon2id hashing and verify
   - lockout/rate-limit checks
5. Refactor service generation scripts to call one bootstrap command (`gntl manager reconcile-and-run`).
6. Add `audit_events` writes for auth/config/service actions.
7. Android app module:
   - Foreground service runner
   - WorkManager reconciliation worker
   - local DB integration

---

## 10) Minimal Acceptance Criteria

- No hard-coded admin credential/token in codebase.
- First run blocks until admin password is created.
- SQLite persists all client states and metadata.
- Autostart starts only enabled + existing clients.
- Disabled/deleted/missing clients never auto-launch.
- Failed auth attempts are rate-limited and lockouts enforced.
- Audit trail exists for critical actions.
- Android implementation uses foreground notification for persistent runtime and WorkManager for compliant background orchestration.
