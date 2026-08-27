# Sanitizer campaign summary

| Field | Value |
|---|---|
| ASan overall | **NOT_RUN** (pending Ubuntu CI) |
| UBSan overall | **NOT_RUN** |
| Combined | **NOT_RUN** |

Local Windows host cannot execute `-Zsanitizer=address|undefined`. Ubuntu GitHub Actions jobs in `.github/workflows/sanitizers.yml` own the PASS/FAIL verdict.
