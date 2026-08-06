# Manual Workflow Runbook

1. Open GitHub Actions for `79cbd8hmgj-wq/RE-MCP`.
2. Select **Build Catalina-Native DeSmuME Debug Bundle**.
3. Choose **Run workflow**.
4. Select `feature/catalina-native-desmume`.
5. Start the run.
6. If it fails, download `desmume-catalina-native-debug-bundle` and inspect `desmume-build-errors.txt` followed by `desmume-build.log`.
7. If it succeeds, verify the ZIP against `desmume-catalina-native-debug.zip.sha256` before extraction.
8. Follow the Catalina acceptance checklist in `README.md`.
