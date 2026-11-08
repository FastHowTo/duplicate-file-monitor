# Duplicate File Monitor v0.6.6

This release consolidates the remaining findings from GitHub issues #1–#10 and improves the scan-report dialog.

## Improvements

- **Dismissible scan reports:** Clicking the backdrop outside a report, pressing Escape, or using Close dismisses the modal. Clicking inside the report (including paths, filters, and pagination) does not. Keyboard focus returns to the opening status link, even if the scan-history row was refreshed.
- **Filesystem mount validation:** New optional `REQUIRE_MOUNT_TYPES=cifs,nfs,nfs4,zfs,xfs` checks active container mountpoints by filesystem type; `any` requires an active mount of any type. Existing `REQUIRE_CIFS_MOUNTS=true` works unchanged when the new setting is omitted. CIFS-specific cache remount handling is **not** applied to NFS, ZFS or XFS.
- **Directory-heavy scans:** Discovery now uses depth-first selection within each volume instead of broad first-in-first-out queues. The dashboard's directory count/current path remain visible. Docker logs emit enumeration heartbeat lines about every 45 seconds even when the file counter is not moving.
- **Intentional ignores:** `SCAN_IGNORE` patterns are documented. Intentional excludes retain previously published inventory and no longer count as recoverable scan warnings; true permission and file-race warnings still appear.
- **Real favicon:** A small SVG favicon loads on the dashboard and login page. Both `/favicon.svg` and legacy `/favicon.ico` requests resolve successfully without requiring an administrator session.
- **Permissions and environment docs:** Explain the container's default UID/GID `10001:100`, optional Compose `user:` override, writable `/data`, read-only NAS mounts, environment variables and obsolete scheduling variables.
- **Update-check privacy:** README clarifies that GitHub release checking happens in the user's browser every six hours; the DFM server does not check GitHub for updates.
- **Version consistency:** Automated tests assert that `app/version.py`, dashboard JS, README and Compose example all match and a corresponding release-note file exists.

Previously completed fixes covered in the original issues were retained and regression-tested: #1 unreadable directories, #2 unreadable/changing files, #4 test dependencies, #6 CSRF and login security, #10 SQLite scratch handling. Issue #8's startup warning for obsolete schedule variables was already present.

## Upgrade

Back up your existing stopped DFM persistent `/data` (SQLite, -wal and -shm as applicable). Keep all NAS mounts read-only and preserve the current Compose environment, credentials, MQTT configuration and Prometheus bearer token. Set your service image to `ghcr.io/fasthowto/duplicate-file-monitor:0.6.6` and update with:

```bash
sudo docker compose pull duplicate-file-monitor
sudo docker compose up -d duplicate-file-monitor
sudo docker compose ps
sudo docker compose logs --tail=100 duplicate-file-monitor
```

**Do not** use `docker compose down -v` or replace the existing data volume. HTTPS through NPMplus is still recommended with `DFM_COOKIE_SECURE=true`; administrator credentials remain unchanged.

## Tests

1. Open a Scan History status hyperlink. Click a dark area outside the report: the report closes. Reopen and click inside, use filters and pagination, then press Escape: the report closes and focus returns to the status link. Close button still works.
2. Verify the login and dashboard browser tabs show the SVG favicon, including an incognito login view. `GET /favicon.svg` should return HTTP 200 with `Content-Type: image/svg+xml`; `/favicon.ico` redirects to it.
3. On a disposable test volume, verify `SCAN_IGNORE` patterns skip matching paths without warnings, preserving previously indexed ignored files. Remove the test pattern after testing.
4. For non-CIFS mounts, set a correct `REQUIRE_MOUNT_TYPES` list and run a test Full Scan. Temporarily specify the wrong type and verify the scan fails safely without publishing inventory; restore the valid type afterward. Do not intentionally unmount NAS shares while scanning.
5. For existing CIFS volumes, leave `REQUIRE_CIFS_MOUNTS=true` if already configured and verify it still validates; `REQUIRE_MOUNT_TYPES` is optional.
6. For directory-heavy filesystems, check the dashboard directory counter/current path and `sudo docker compose logs -f duplicate-file-monitor` for heartbeat messages about every 45 seconds.
7. Check full/quick scans, warnings, historical reports, exact archived duplicate paths, per-volume figures, Home Assistant MQTT and Prometheus/Grafana. Verify login, logout and CSRF protections remain intact.
8. Confirm the container still runs non-root and can read the mounted test paths and write its private /data volume. Only change Compose `user:` if a permissions mismatch actually requires it.
