# `vuln-db` - Local vulnerability database CLI

`vuln-db` builds and refreshes the local SQLite database
(`data/vulnerability.db` by default) that both server modes (`vuln-server
--mode mcp` and `vuln-server --mode rest`, see [`docs/vuln-server.md`](vuln-server.md))
read from. It syncs data from the NVD CVE feeds, the FIRST EPSS feed, and
(on `--init`) the NVD CPE dictionary and CPE Match Criteria feeds.

Always run it from the repo root (paths like `data/vulnerability.db` are
resolved relative to the current working directory).

## First run

```powershell
vuln-db --init
```

`--init` creates the database tables (if missing) and does a full sync:

- NVD CVE + EPSS data (always synced, every run)
- CPE dictionary (`resolve_cpe`/`GET /cpe/resolve`), ~82MB compressed
- CPE Match Criteria feed (`search_cves_by_cpe`/`GET /cves/search-by-cpe`
  exact matching), ~795MB compressed

It's required before first use, is safe to rerun, and can take a while on
first run given the size of the CPE Match Criteria feed.

## Subsequent refreshes

```powershell
vuln-db
```

Without `--init`, only the NVD CVE/EPSS data is refreshed (each year's feed
is only re-downloaded if NVD reports it as modified since the last sync).
The CPE dictionary and CPE Match Criteria feed are NOT touched - rerun with
`--init` if you need to refresh those too.

## Flags

| Flag | Values | Default | Description |
| --- | --- | --- | --- |
| `--init` | flag | off | Create the schema (if missing) and fully (re)populate it: NVD CVE/EPSS data plus the CPE dictionary and CPE Match Criteria resolution feeds. Forces a full re-download/re-parse of every year of the NVD CVE feed. |
| `--temp-dir` | path | `""` (system temp behaviour, see code) | Temporary directory used to store downloaded feed files while they're parsed. |
| `-f`, `--fetch-mode` | `API` \| `LOCAL` | `API` | `API` downloads feeds live from NVD/FIRST/CISA. `LOCAL` reads already-downloaded feed files from `--temp-dir` instead (useful for offline/air-gapped runs, or to avoid re-downloading large archives while iterating). |

## Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `CVE_DATABASE_PATH` | `data/vulnerability.db` | Path to the SQLite database file, read/written by `vuln-db` and read by both `vuln-server` modes (via `tools/vulnerability_service.py`). |

## Examples

```powershell
# First-time full sync (live NVD/EPSS/CISA feeds)
vuln-db --init

# Regular refresh (CVE/EPSS only, live feeds)
vuln-db

# Offline: re-parse feed archives already downloaded into ./feeds
vuln-db --init --fetch-mode LOCAL --temp-dir ./feeds

# Use an alternate database file
$env:CVE_DATABASE_PATH = "data/vulnerability-staging.db"
vuln-db --init
```
