# DFM 0.6.2

- Persist Duplicate Directory Trees analysis results in the existing SQLite database, across browser refreshes, restarts and version updates.
- Rehydrate the saved report on initial dashboard startup.
- Mark reports stale when published inventory changes; refresh only when Analyze inventory is clicked.
- Click any numeric directory header to sort descending or ascending; default is Potential savings descending. Keyboard-accessible sorting and remembered sort selection.
- Unchanged read-only NAS access, scanner finalization, duplicate accounting and scan history.
- First Analyze inventory request creates the cache table and saves up to 500 qualifying groups; no new mount access.
