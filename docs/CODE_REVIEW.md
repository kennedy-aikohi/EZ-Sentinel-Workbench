# Code Review Notes

## Bugs fixed

1. **GUI freezing**
   - Root cause: recursive evidence searches were happening during command preview and normal UI actions.
   - Fix: added `ArtifactIndex` and asynchronous evidence indexing.

2. **Long parser output memory pressure**
   - Root cause: full stdout/stderr could be accumulated until process completion.
   - Fix: stdout/stderr now stream line-by-line to the GUI. bstrings output is written directly to a file.

3. **Parser mixing**
   - Root cause: generic extra args and duplicate tool locations could make commands hard to inspect.
   - Fix: tool-lock preview, exact executable mapping, and blocked `.exe` paths in Extra Args.

4. **Unsupported switches**
   - Removed old LECmd `--ld --fd` profile.
   - Kept WxTCmd as `-f ActivitiesCache.db` only.
   - Kept AmcacheParser CSV-only for the installed build.
   - Kept RECmd argument builder to prevent empty `--sk` and similar failures.

## Production notes

- Use `BUILD_WINDOWS_EXE.bat` for Windows packaging.
- Prefer the PyInstaller onedir output for faster launch and easier troubleshooting.
- Keep EZ Tools updated separately and re-check `-h` output when Zimmerman tools change switches.
