# Duplicate File Monitor v0.6.10.2

## Improved

- **Stable column positions:** The main Duplicate Files and Duplicate Directories tables use fixed-layout tables with explicit numeric-column widths. Long filenames and directory paths wrap inside a flexible first column; sorting, pagination and expanding paths cannot shift column headings. On narrow screens the tables scroll horizontally without changing their geometry.
- **Redesigned archived scan reports:** Scan status, start/completion timestamps, duration and saved inventory metrics appear in a compact summary above three independently collapsible sections: Per-volume results, Warnings and Duplicate Files. All three sections open collapsed.
- **Sortable per-volume results:** Archived per-volume statistics use fixed-width sortable headings. Additional saved changes in logical size, duplicates and wasted space, plus the previous scan time, remain accessible by expanding the corresponding volume. Saved scan totals remain separate from the sorted volume rows.
- **Warnings without excessive scrolling:** Saved recoverable warnings are initially hidden, then available with consistent pagination (25, 50 or 100 records per page). Older reports explicitly identify unavailable warning details.
- **Compact archived duplicate-file groups:** Historical duplicate matches render as a sortable four-column table. Filenames and per-group matching paths remain collapsed until the user opens an individual group. The archived SHA-256 digest, full paths, and Scanned/Outside Scan Scope indicators are retained.
- **Uniform archived navigation:** Archived duplicates support filename, file size, copy count, and wasted-space column sorting in both directions, archive-only filename/path search, volume filtering, and the same centered `<< < [page] > >>` controls with a right-aligned 25/50/100 records-per-page selector used elsewhere in DFM. Sorting and filtering operate over the full archived group set before paging.
- **Read-only historical integrity:** Archived duplicate sorting continues to read immutable saved scan snapshots, never present-day NAS files. Existing duplicate matching, full and quick scan behavior, directory analysis, warning recording, monitoring integrations, authentication and privacy safeguards are unchanged. No new outbound connections or source-file writes are introduced.

## Upgrade

Keep your existing Compose settings, credentials, persistent database, integrations, and read-only NAS mounts. Back up the persistent `/data` volume (including SQLite WAL and SHM files) with the container stopped before upgrading. Set the image to `ghcr.io/fasthowto/duplicate-file-monitor:0.6.10.2`, then run:

```bash
sudo docker compose pull duplicate-file-monitor
sudo docker compose up -d duplicate-file-monitor
```

Do not run `docker compose down -v`. No new environment variables or database migrations are required.
