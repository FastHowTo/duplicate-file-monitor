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
- **Version consistency:** Version identifiers are aligned across application, dashboard, documentation and Compose example.

Previously completed fixes covered in the original issues were retained: #1 unreadable directories, #2 unreadable/changing files, #4 test dependencies, #6 CSRF and login security, #10 SQLite scratch handling. Issue #8's startup warning for obsolete schedule variables was already present.

## Upgrade

Back up your existing stopped DFM persistent `/data` (SQLite, -wal and -shm as applicable). Keep all NAS mounts read-only and preserve the current Compose environment, credentials, MQTT configuration and Prometheus bearer token. Set your service image to `ghcr.io/fasthowto/duplicate-file-monitor:0.6.6` and update with:

```bash
sudo docker compose pull duplicate-file-monitor
sudo docker compose up -d duplicate-file-monitor
sudo docker compose ps
sudo docker compose logs --tail=100 duplicate-file-monitor
```

**Do not** use `docker compose down -v` or replace the existing data volume. HTTPS through NPMplus is still recommended with `DFM_COOKIE_SECURE=true`; administrator credentials remain unchanged.
