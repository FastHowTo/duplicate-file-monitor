# DFM v0.6.0.1 — Remove unauthorized file-loss threshold

- Removed the entire count-based scan rejection including the below-20%-of-baseline threshold, zero-file special case and `ALLOW_LARGE_REMOVALS` override.
- Intentional large deletions, including cleaning out entire directory trees, can now be recorded normally after successful enumeration.
- Existing CIFS mount validation, scanner enumeration failure checks, read-only source mounts, and atomic publication protections remain.
- No database migration or Docker Compose changes.
- This fix does not prove the mount is valid if a remote server incorrectly presents an accessible but incomplete tree; confirm source availability before bulk scans.
