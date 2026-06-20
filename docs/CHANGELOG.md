# Changelog

## v6.2 - Hayabusa Detection Integration

- Included third-party Hayabusa v3.9.0 under `tools\hayabusa` with upstream rules and config.
- Added locked Hayabusa wrapper profiles for EVTX folder CSV output, EVTX folder CSV plus HTML report, single EVTX, and JSON/JSONL Windows event logs.
- Added project-local tool discovery so bundled tools are found in addition to the configured EZ Tools Root.
- Added parser log backpressure to prevent high-volume stdout/stderr from freezing the GUI.
- Replaced Unicode tool-list status glyphs with ASCII markers for more reliable Windows display.

## v6.0 - Performance & Hardening Edition

- Replaced UI-thread evidence recursion with a background evidence indexer.
- Added asynchronous EZ Tools scanner.
- Added cached artifact resolution to stop command preview freezes.
- Added live stdout/stderr streaming into the GUI log.
- Added direct stdout-to-file capture for bstrings.
- Added bounded GUI log retention.
- Added safety file limit for evidence indexing.
- Added professional logo assets.
- Kept RECmd argument builder and tool-lock protections.
- Kept corrected profiles for LECmd, WxTCmd, AmcacheParser, RECmd, and SQLECmd.
