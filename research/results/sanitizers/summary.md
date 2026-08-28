# Sanitizer campaign summary

| Field | Value |
|---|---|
| ASan overall | **NOT_RUN** (CI run 33104978058: tests passed; script bug fixed) |
| UB checks (`-Zub-checks`) overall | **NOT_RUN** (LLVM UBSan BLOCKED) |
| LLVM UBSan | **BLOCKED** |
| Combined | **NOT_RUN** |

Local Windows host cannot execute `-Zsanitizer=address|undefined`. Ubuntu GitHub Actions jobs in `.github/workflows/sanitizers.yml` own the PASS/FAIL verdict.
