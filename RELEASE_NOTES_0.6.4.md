# Duplicate File Monitor v0.6.4 — Authentication, recovery and archived scan reports

## Upgrade checklist — authentication is mandatory

**IMPORTANT:** This release enables built-in login protection for the dashboard and API. **There is no default password.** Before switching to the v0.6.4 image, add a private one-time setup token to your existing Compose configuration. Keep your existing `docker-compose.yml`, source mounts, SQLite database and MQTT settings; **do not replace your production configuration with the public example**.

1. Save a backup of your persistent `/data` volume, including the SQLite database and WAL/SHM files, with DFM stopped. Retain the old image version for rollback.
2. Generate a one-time setup token locally using `openssl rand -hex 32`. Generate a separate independent token for Prometheus with the same command if you scrape `/metrics`.
3. Add these entries to the existing DFM service's `environment:` block, inserting your private values locally (never commit them):
   ```yaml
   DFM_SETUP_TOKEN: "<your-own-random-token-of-at-least-24-characters>"
   DFM_COOKIE_SECURE: "true"
   DFM_METRICS_TOKEN: "<separate-random-token-if-Prometheus-is-used>"
   ```
4. Change only the image tag to `ghcr.io/fasthowto/duplicate-file-monitor:0.6.4`. Preserve the existing `/data` mapping and all read-only source mount mappings.
5. From the existing Compose directory:
   ```sh
   sudo docker compose pull
   sudo docker compose up -d
   sudo docker compose logs --tail=100 duplicate-file-monitor
   ```
6. Open DFM through **HTTPS** (for example, via an existing trusted reverse proxy). The first page prompts for a username, a strong password of at least 12 characters, and the one-time setup token. Once that administrator is registered, subsequent visits show the login page.
7. Keep the setup token private, then remove `DFM_SETUP_TOKEN` from Compose after successful setup if desired. It is not used to log in after an administrator exists. Restart the service after removing it.

### HTTPS and cookie configuration
`DFM_COOKIE_SECURE=true` (default) marks the session cookie Secure; this is the recommended setting for HTTPS reverse-proxy access. If accessing the server over **unencrypted HTTP on a trusted local network only**, set `DFM_COOKIE_SECURE: "false"` explicitly before setting up your account. Never expose the HTTP service directly to the public internet. A proxy must forward the original Host header for the API's same-origin checks.

### Prometheus / Grafana authentication
The `/metrics` endpoint now requires an authenticated session or a separate `Authorization: Bearer <DFM_METRICS_TOKEN>` header. When using Prometheus, update its scrape job to use a bearer token with the same secret stored privately (for example, in a Prometheus-owned token file), then reload Prometheus. Do not use the administrator password as a monitoring token. The unauthenticated `/api/startup` and `/health` endpoints remain available for health checking; all inventory and management APIs require login.

### Account management and sessions
A single administrator account is supported. Under Settings → Administrator account, enter the current password and a new username/password to change credentials; this invalidates all current sessions. Use Logout when finished. Session cookies are HTTP-only, SameSite=Strict, and expire after 24 hours.

### Scan outcomes and reports
Completed scans show **Completed** (green) or **Completed with X warnings** (amber). Unrecoverable scans show **Failed** (red); user-terminated scans show **Cancelled** (gray). The scan summary and history expose **View scan report** for new scans: an immutable record of time, duration, selected-volume metrics, deltas against the previous completed scan, and full warning paths. Historical v0.6.3 scans cannot be retroactively supplied with per-volume logical-size snapshots.

Recoverable inaccessible directories and files being modified during hashing are logged and handled without discarding the entire scan. Existing inventory is preserved instead of being mistaken for a deletion or an increase in lifetime savings. Filesystem I/O failures and database corruption remain fatal.

### Additional improvements
- Fix SQLite scratch-directory initialization for large queries in read-only containers.
- Show directory-enumeration activity and current path while scanning.
- Reject state-changing cross-origin and non-JSON requests; protect APIs against CSRF.
- Log warnings for deprecated scheduling environment variables.

### Privacy and storage
This public release contains only source code, generic examples and documentation. Production SQLite files, MQTT credentials, local Compose files, NAS paths, network addresses and secrets are **not** included. Source volumes are still read-only; DFM does not delete, move, rename, hardlink or modify files.

### Known limits
A scan with inaccessible content may retain previously verified inventory that could not be rechecked; its report identifies the affected paths. Never treat reported reclaimable storage as proof of actual deletions. Historical report JSON records are stored in the existing SQLite data volume and must be included in backups.
