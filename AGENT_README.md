# Guide for AI agents / researchers

This repo is easiest to run in **Docker** so tool versions match the image. Use this file to scan without burning tokens on raw logs.

## Run scans (recommended)

```bash
export REPO_PATH=/absolute/path/to/repo
docker compose up --build
```

Why Docker here:

1. **Same binaries** — TruffleHog, Gosec, Semgrep, Trivy, Govulncheck, etc. match the image; fewer “works on my machine” failures.
2. **Isolated output** — Host repo is mounted read-only at `/scan`; results land under `./results` on the host.

## Token budget: read this first

Do **not** read every `results/raw_*.json` unless you must.

1. Start with **`results/actionable_findings.json`** — deduplicated, normalized, smaller.
2. Use **`correlations`** — multiple tools on the same code increase confidence.
3. Raw per-tool dumps are only for debugging normalizers.

## Output layout

| Path | Use |
|------|-----|
| `results/actionable_findings.json` | Primary structured input |
| `results/report.html` | Human summary in a browser |
| `results/raw_*.json` | Deep dive / suspected parser miss |

## Practical notes

- **Paths in Docker** — Repo root is `/scan` inside the container; paths in findings refer to that mount.
- **Tune load** — Lower `max_parallel_scans` in `configs/orchestrator.yaml` if the host struggles.
- **Tool configs** — Under `configs/tools/` (create with `./orchestrator config init` when working outside Docker).

---

*Written for agent workflows on AFSS.*
