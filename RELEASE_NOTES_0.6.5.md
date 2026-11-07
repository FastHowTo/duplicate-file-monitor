# Duplicate File Monitor v0.6.5

Release for existing v0.6.4 installations. **Read-only NAS scanning is unchanged.** Scan results and archived reports are stored in the persistent SQLite data volume. Back up the stopped container's complete /data directory (including inventory.sqlite3, -wal and -shm when present) before upgrading; do not use docker compose down -v.

## Improvements

- **Scan Progress:** Successful scans have green "Completed" text and a green progress bar; recoverable-warning success shows amber text/bar; failed status and its displayed bar are red; cancelled status and its displayed bar are gray. Active scan progress remains blue.
- **Scan History:** The colored scan Status text is a hyperlink that opens the corresponding report. Removed the redundant report button from each history row.
- **Legacy scan reports:** On first opening an older scan with no archived report, DFM reconstructs a report from historical scans and volume_scans records and saves it once as an immutable report. Missing values (historical logical size, old warnings, exact file paths) are labeled unavailable, never inferred from today's files. No NAS re-scan occurs.
- **Complete scan-specific duplicate paths:** Newly completed Full and Quick Scans archive all *confirmed* duplicate groups that touch a scanned volume, including previously known duplicates, with the full file path and filename for each member. Cross-volume matching paths outside selected volumes are visibly distinguished. The report viewer supports path search, selected-volume filtering, sorting by redundant bytes/file size/copy count, and 25-group pages. The global Duplicate Files dashboard remains unchanged.
- **Immutable snapshots:** New report duplicate groups are compressed and committed atomically with the published inventory and scan outcome. Cancelled or failed scans do not archive uncommitted duplicate groups. Existing reports are never overwritten by reconstruction.

## Deployment

Image: `ghcr.io/fasthowto/duplicate-file-monitor:0.6.5`

Use the existing Compose service, NAS \`:ro\` mounts, database volume, and environment settings. The v0.6.4 administrator username/password and one-time setup remain valid. HTTPS via NPMplus remains recommended; \`DFM_COOKIE_SECURE=true\` prevents browser session cookies over HTTP. Prometheus scraping continues to require the already configured independent \`DFM_METRICS_TOKEN\`.

```bash
sudo docker compose pull duplicate-file-monitor
sudo docker compose up -d duplicate-file-monitor
sudo docker compose ps
sudo docker compose logs --tail=100 duplicate-file-monitor
```

Do not remove the existing /data bind mount or use `down -v`. Prometheus, MQTT, and your existing scan settings are preserved.

## Important archive considerations

New compressed duplicate group snapshots add SQLite storage on every successful scan. The amount depends on duplicate-group membership and path lengths; frequent scans of very large inventories will grow /data over time. This is necessary to preserve exact historical duplicate paths without relying on a mutable current inventory. Archive search across many compressed groups can take longer than an unfiltered page.

Legacy reports can recover only data actually stored at the original scan time. DFM cannot prove old warnings were absent, rebuild missing historical logical sizes, or recover exact file paths for scans performed before v0.6.5.

## Acceptance tests

1. Verify green Completed, amber Completed with X warnings, red Failed and gray Cancelled styling in Scan Progress.
2. In Scan History, click status text to open a report; ensure old per-row report buttons are gone.
3. Click a pre-v0.6.4 history row: reconstructed report shows old values, missing fields as unavailable; reopen it later and confirm no values changed.
4. Full Scan a test volume with known duplicates, then Quick Scan without changes. The Quick report must list previously known duplicate paths.
5. Scoped Scan one volume with matching files on another volume: report includes full paths and labels which paths were scanned or outside scan scope.
6. Change a file and scan again, then reopen the older report: archived duplicate membership and paths must remain unchanged.
7. Test search, volume filter, sort and pagination on archive groups.
8. Confirm unchanged global Duplicate Files dashboard, Home Assistant MQTT and Prometheus metrics.
