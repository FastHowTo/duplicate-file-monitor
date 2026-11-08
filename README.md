# Duplicate File Monitor (DFM)

**Version 0.6.10.1** — A read-only, Docker-hosted duplicate-file and duplicate-directory inventory tool for network storage.

DFM inventories selected directories, identifies SHA-256-confirmed duplicate files, analyzes identical directory trees, and estimates redundant logical storage. **It never deletes, renames, moves, or alters source files.** Cleanup is a separate, manual administrator decision.

## Features

- Full and Quick Scans, including selected volumes
- Scheduled scans
- Duplicate-file grouping and exact duplicate-directory-tree reporting
- Automatically refreshed duplicate-directory reports after completed scans, with independent analysis status, sortable columns, and compact 25/50/100-row pagination
- Collapsible Duplicate Files, Duplicate Directories, and Scan History sections; collapsed by default, retaining expansion during the current login/browser session only
- Duplicate root-directory location count in the global summary and last-update dates in report headings
- Dropdown page selection and compact first/previous/next/last controls on all three reports
- Duplicate-file sorting by clickable table columns, matching duplicate-directory behavior, and inline filename search controls
- Release notifications compare against the served application version, including four-component patch versions
- Global and per-volume inventory statistics and scan history
- Estimated lifetime logical space savings from verified duplicate removals
- MQTT publishing for Home Assistant
- Prometheus metrics
- Persistent SQLite inventory
- Built-in administrator login, authenticated API and Prometheus bearer-token access
- Immutable archived scan reports, including full paths of confirmed duplicate groups in selected volumes
- On-demand, permanently saved legacy reports, with unknown historical details explicitly marked unavailable
- Recoverable warning tracking
- HTTP dashboard

## Install with Docker Compose

1. Mount the storage you want to scan on the Docker host first.
2. Copy `docker-compose.example.yml` to `docker-compose.yml`. The example uses the published image `ghcr.io/fasthowto/duplicate-file-monitor:0.6.10.1` (no local build required).
3. Change `/path/to/your/mounted/files` to the actual host mount path; add more **read-only** mounts and colon-delimited `SCAN_ROOTS` paths as needed.
4. Start DFM:

```sh
sudo docker compose up -d
```

**Authentication (mandatory since v0.6.4):** Add a private `DFM_SETUP_TOKEN` (at least 24 random characters, e.g. output of `openssl rand -hex 32`) to your existing Compose environment before upgrading. By default, login requires HTTPS so the Secure session cookie works. First visit: choose your username and a 12+-character password, and enter the setup token. For a trusted HTTP-only LAN installation set `DFM_COOKIE_SECURE: "false"` explicitly. A separate `DFM_METRICS_TOKEN` (at least 24 random characters) may be configured for Prometheus bearer-token scrapes. **Read [v0.6.10.1 release notes](RELEASE_NOTES_0.6.10.1.md) before upgrading**, particularly the data backup and WAL checkpoint behavior.

The **user's browser**, not the DFM server, checks GitHub Releases every six hours for a newer published, non-prerelease version. This is a browser-only request to GitHub; an offline browser simply does not display an update notice. The server does not contact GitHub for update checks and never installs updates automatically.

Browse `http://your-docker-host:18080`. Allow the initial Full Scan to establish an inventory before relying on Quick Scan results.

**Security:** Built-in authentication is enabled by default. Use HTTPS, restrict network exposure, and never forward its plain HTTP port directly to the public internet. The SQLite data volume may contain MQTT connection credentials; protect its backups.

**Important:** Confirm that your NAS shares are fully mounted and accessible before scanning. DFM's logical space estimates do not account for ZFS snapshot retention, compression, deduplication, or hard links. Directory analysis uses confirmed hashes and may exclude empty directories or files without full hashes.

## File permissions and mount safety

The image runs as **UID 10001 / GID 100** by default. That account needs read and directory-traverse permission on every source path, and **write** permission to the persistent `/data` volume for SQLite, WAL, session information and the `/data/.sqlite-tmp` scratch directory. All NAS/content mounts should remain `:ro`, including when using an alternate container user.

To match a host account that can read your NAS shares, optionally set this under the existing Compose service (use your actual host UID/GID):

```yaml
user: "1000:1000"
```

Check host ownership with `id` and `ls -ld /path/to/your/data`. **Before changing the user**, make sure the existing DFM data directory and SQLite files are writable by that UID/GID, including `/data/.sqlite-tmp`. For host bind-mounted data, adjust that private data directory's ownership/ACL as appropriate; changing the Compose user does not change host filesystem permissions. Docker-managed named volumes are seeded with the default UID/GID. Do not recursively open NAS share permissions just to work around a scan warning; prefer a narrow read-only ACL.

Unreadable subdirectories and transient file permission/change errors are logged as recoverable warnings in modern reports, without treating old indexed files as deleted. Fatal I/O/database errors still fail the scan.

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `DB_PATH` | `/data/inventory.sqlite3` | Persistent SQLite inventory and history |
| `SCAN_ROOTS` | `/scan` | Colon-separated in-container scan-root directories |
| `HTTP_PORT` | `8080` | HTTP listener inside the container |
| `SCAN_BANDWIDTH_MBPS` | `250` | Content-read throttle; 0 disables throttling |
| `SCAN_FILE_WORKERS` | `4` | File and directory worker count (1–16) |
| `REQUIRE_MOUNT_TYPES` | Unset | Comma-separated allowed filesystem types, e.g. `cifs,nfs,nfs4,zfs,xfs`. Every scan root must be an active **container mountpoint** of an allowed type. `any` requires a mountpoint of any filesystem type (useful for bind mounts). Empty means fall back to the legacy switch. |
| `REQUIRE_CIFS_MOUNTS` | `false` | Backward-compatible CIFS-only mount safety check; honored when `REQUIRE_MOUNT_TYPES` is unset/empty |
| `SCAN_IGNORE` | Empty | Colon-separated filename or relative-path glob patterns (e.g. `.cache:@eaDir:#recycle:*.tmp`). Excluded paths are skipped without warnings. Previously inventoried files under excluded paths remain recorded to prevent false deletions and inaccurate lifetime-savings credit; those entries are not revalidated while excluded. |
| `DFM_SETUP_TOKEN` | Unset | Random 24+-character one-time secret used to create the first administrator; remove after setup |
| `DFM_COOKIE_SECURE` | `true` | Require HTTPS for browser login session cookies. Set `false` only on a trusted HTTP-only LAN |
| `DFM_METRICS_TOKEN` | Unset | Separate 24+-character bearer secret for Prometheus `/metrics` |
| `SQLITE_TMPDIR`, `TMPDIR` | `/data/.sqlite-tmp` | Set in the image **before** `sqlite3` imports; the directory must be writable |

Schedule intervals and MQTT broker settings are configured in the DFM dashboard, not through deprecated `SCAN_INTERVAL_SECONDS` or `SCAN_ON_START`. If those old variables are present, startup logs a warning and ignores them. The repository's Compose example deliberately omits these obsolete variables.

**Mount validation notes:** `REQUIRE_MOUNT_TYPES` checks `/proc/self/mountinfo` **inside the container**. Docker bind mounts report their underlying filesystem type (e.g. ZFS, XFS or CIFS), not a literal `bind` type. The check requires the configured scan root itself to be a mountpoint and does not replace checking that your host's remote storage is genuinely mounted before starting DFM. Existing CIFS-specific cache-remount handling is retained only for CIFS filesystems, never applied to local ZFS/XFS/NFS.

**File discovery:** The dashboard shows a simple discovery status and the Files Discovered count, without directory counters or current directory paths. Docker logs retain operational heartbeat diagnostics during long directory enumeration.

## License

Free noncommercial use under [PolyForm Noncommercial 1.0.0](LICENSE.md). Commercial deployment requires a separate license; see [Commercial Licensing](COMMERCIAL.md) or email **jeff@fasthowtochannel.com**.

Copyright © 2026 FastHowTo.
