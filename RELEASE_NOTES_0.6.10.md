# Duplicate File Monitor v0.6.10

## Changed

- **Collapsible reports:** Duplicate Files, Duplicate Directories, and Scan History now have compact, clickable headings with upward/downward carets. All three start collapsed for a new login/browser session. Expansion states remain unchanged while scans run and complete; signing out or signing in resets them, and closing the browser ends the normal session.
- **Last updated information:** Collapsed Duplicate Files and Duplicate Directories headings display their latest committed inventory or completed directory-analysis timestamps. The Scan History heading shows the most recent scan's start time. Directory analysis continues to show the existing animated ellipsis while updating, without presenting stale cleanup results.
- **Duplicate root directory count:** A fifth global summary card reports the number of individual directory locations listed in the saved duplicate-directory report. This differs from the number of matching groups and covers all locations within the existing limit of up to 500 saved matching groups. The card shows no stale count while inventory analysis is pending or unavailable.
- **Consistent pagination:** Duplicate Files, Duplicate Directories, and Scan History now use 25, 50, or 100 records per page. Centered navigation contains compact `<<`, `<`, a scrollable native page-number dropdown, `>`, and `>>` controls; the records-per-page selector is right-aligned at the bottom of each expanded section. Page selection updates immediately without a Go button.
- **Full scan history access:** Pagination now queries the complete saved scan history rather than truncating the visible list. Per-volume filters continue to include matching all-volumes scans; historical records and their archived reports remain unchanged.
- **Unchanged safeguards:** Directory-tree SHA-256 matching logic, independent post-scan analysis, scan finalization, read-only source access, authentication, permissions, MQTT, Prometheus, and existing privacy behavior are unchanged. No additional external connections or data transmission have been introduced.

## Upgrade

Keep the existing Compose configuration, credentials, persistent database, monitoring settings and read-only NAS mounts. Back up the persistent `/data` volume, including its SQLite WAL and SHM files, with the container stopped before upgrading. Change the image to `ghcr.io/fasthowto/duplicate-file-monitor:0.6.10`, then run:

```bash
sudo docker compose pull duplicate-file-monitor
sudo docker compose up -d duplicate-file-monitor
```

Do not use `docker compose down -v`. No additional configuration variables or schema migrations are required.
