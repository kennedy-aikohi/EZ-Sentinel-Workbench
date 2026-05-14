# EZ Sentinel Workbench v6.0

Author: **KENNEDY AIKOHI**  
LinkedIn: https://www.linkedin.com/in/aikohikennedy/

EZ Sentinel Workbench is a Windows GUI launcher for Eric Zimmerman command-line tools. It is designed for KAPE-style evidence folders and collected Windows artifacts.

## What changed in v6

- Fixed UI freezing by moving EZ Tools scanning and evidence indexing into background threads.
- Stopped heavy recursive file discovery from running every time the command preview refreshes.
- Added a cached evidence index for paths like `$MFT`, `ActivitiesCache.db`, SRUDB, registry hives, EVTX, Prefetch, Users, and Recycle Bin.
- Added live log streaming for long parsers so the GUI remains responsive.
- Redirected bstrings stdout directly to a file to avoid memory exhaustion.
- Added bounded GUI log trimming.
- Kept parser locking so profiles cannot accidentally run against the wrong executable.
- Added a professional logo in PNG/SVG/ICO format.

## Recommended case setup

Example:

```text
EZ Tools Root:  C:\Users\kenne\Desktop\EZ TOOLS\net9
Evidence Root:  C:\Users\kenne\Desktop\DC01_Kape\C
Output Root:    C:\Users\kenne\Desktop\Results
```

Click:

1. **Scan EZ Tools**
2. **Index Evidence**
3. Pick a parser/profile
4. Review **Tool locked to** and **Command Preview**
5. Click **Analyze Selected**

## Build executable

Run:

```cmd
BUILD_WINDOWS_EXE.bat
```

Output:

```text
dist\EZSentinelWorkbench\EZSentinelWorkbench.exe
```

`--onedir` is used instead of `--onefile` because this app has assets, docs, logs, and forensic workflow configuration. It starts faster and is easier to troubleshoot.

## Screenshot

![EZ Sentinel Workbench GUI](assets/sample.png)

