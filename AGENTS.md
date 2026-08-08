# AGENTS.md

A local MCP server (FastMCP, streamable-http transport) backed by a
pre-populated SQLite DB. All MCP tools are 100% local at query time — no
outbound network calls, no API key required. (The separate `vuln-db` CLI used
to *build/refresh* that DB does make live network calls — see below.)

## Tools

- `get_cve_by_id(cve_id)` — full detail for one CVE (renamed from
  `get_vulnerability_data`; keep README/opencode references in sync if
  renamed again).
- `batch_search_cves(cve_ids: list[str])` — like `get_cve_by_id` but batched;
  returns a dict per CVE id (raw fields, not the formatted `render_mcp()`
  text) with a `found` flag for ids missing locally.
- `search_cves_by_keyword(keyword, limit=50)` — SQL `LIKE` substring match on
  `cves.description`, ordered by CVSS score desc. No FTS/ranking, just a
  substring scan.
- `get_epss_score(cve_ids: list[str])` — EPSS score/percentile as raw
  fractions (0-1), unlike `render_mcp()` which shows them ×100 for display.
- `check_kev_status(cve_ids: list[str])` — boolean CISA KEV membership only.
  `date_added`/`known_ransomware_use` are NOT available (not stored locally,
  would require syncing the live CISA KEV JSON feed — intentionally deferred).
- `get_nvd_sync_status()` — reads the `metadata`/`nvd_meta` tables to report
  local data freshness.
- `search_cves_by_cpe(cpe, limit=50)` — CVEs affecting a given CPE 2.3 string
  (full or partial, e.g. `cpe:2.3:a:apache:log4j:2.14.1` or just
  `cpe:2.3:a:apache:log4j`). Reads the `cpe_matches` table (populated from
  each CVE's `configurations` block during `vuln-db` sync). Vendor/product are
  matched exactly; each result reports a `match_precision`:
  - `"exact"` — the version was checked against NVD's own resolved concrete
    CPE list via `matchCriteriaId` (`cpe_match_resolutions` table, needs
    `vuln-db --init`).
  - `"approximate"` — fallback hand-rolled version/range comparison
    (`DatabaseClient._version_sort_key` — numeric-aware, no external dep)
    when no resolution data is available for that matchCriteriaId; escaped
    characters or unusual version schemes may not resolve correctly.
  Empty list (with a logged warning) if `cpe_matches` doesn't exist yet — run
  `vuln-db --init`.
- `resolve_cpe(keyword, limit=50)` — keyword search (vendor/product/title)
  against the `cpe_dictionary` table. This table is **not** populated by a
  normal `vuln-db` run — it requires the separate, large, opt-in
  `vuln-db --init` sync (~1.8M entries, ~82MB compressed, from the NVD CPE
  2.0 bulk feed). Empty list (with a logged warning) if never synced.

## Setup

- Single manifest: `pyproject.toml` lists every dependency needed to both
  **run the MCP server** (`fastmcp`, `mcp`, etc.) and use the **`vuln-db`
  CLI** (`requests`, `colorama`). Install everything with
  `pip install -e .` (editable install), which also registers the `vuln-db`
  console script (`project.scripts` -> `cli.db:main`). There is no
  `requirements.txt` anymore — don't reintroduce a second manifest.
- Python 3.9+, venv recommended for the install above.
- `data/vulnerability.db` is git-ignored. Either unzip the pre-built
  `data/vulnerability.zip` into `data/` (see README, may be schema-outdated),
  or build/refresh it yourself with `vuln-db` (see below).

## Running the MCP server

- Always run from the **repo root**, not from `src/`:
  ```powershell
  python src/vulnerability-mcp-server.py
  ```
  `DatabaseClient` opens `data/vulnerability.db` as a path relative to the
  current working directory (not relative to the script), so running from
  `src/` breaks the DB lookup.
- Server listens on `http://0.0.0.0:8000/mcp` (hardcoded, no env var for port/host).
- No automated test suite, linter, or CI config exists in this repo — don't
  assume `pytest`/`ruff`/`black` are available or invoke them. `src/test.py`
  (a former ad-hoc manual script for exercising `DatabaseClient`/`Vulnerability`
  directly) and `hello_world.py` have been removed.

## Building/refreshing the database (`vuln-db` CLI)

- After `pip install -e .`, run `vuln-db [options]` (repo root, or set
  `CVE_DATABASE_PATH` env var if not running from repo root — defaults to
  `data/vulnerability.db`). Implemented in `src/cli/db.py` -> `DataBaseManager`
  in `src/tools/database_clients.py`.
- Flags (`src/cli/db.py::_init_args_parser`):
  - `--init` — create tables if missing (`CREATE TABLE IF NOT EXISTS`,
    idempotent/safe to rerun) AND fully populate the CPE side of the schema:
    the **full CPE dictionary** (`cpe_dictionary` table, backs `resolve_cpe`)
    from the NVD CPE 2.0 bulk feed (`nvdcpe-2.0.tar.gz`, ~82MB compressed /
    ~1.8M entries, ~1-2 minutes), and the **CPE Match Criteria resolution
    feed** (`cpe_match_resolutions` table, backs `search_cves_by_cpe`'s
    `"exact"` match precision) from the NVD CPE-Match 2.0 bulk feed
    (`nvdcpematch-2.0.tar.gz`, ~795MB compressed / ~3.5GB uncompressed - much
    larger/slower). No separate flags for these: `--init` is meant to fully
    (re)build the database in one shot; regular (non-`--init`) runs only
    refresh CVE/EPSS data and skip the CPE feeds entirely (no freshness
    check network round-trip either). **Required on first run**, and again
    after a schema change adds new tables.
  - `-f/--fetch-mode {API,LOCAL}` (default `API`) — `API` downloads live from
    NVD (`nvdcve-2.0-<year>.json.gz`) + EPSS (FIRST); `LOCAL` reads
    pre-downloaded files from `--temp-dir` instead (no network), but note it
    always treats every year as stale (see caveat below) so it always
    reprocesses on every run.
  - `--temp-dir` — scratch dir for downloaded/local `.json.gz`/`.tar.gz` files.
  - Both CPE bulk feeds use the same `.meta` freshness format as the per-year
    CVE feeds (`lastModifiedDate/size/zipSize/gzSize/sha256`) and reuse
    `nvd_meta`/`_is_feed_up_to_date` under the pseudo-year keys `"CPE"` /
    `"CPE_MATCH"` (same pattern as the `"EPSS"` row) — so re-running `--init`
    when already up to date is cheap (one `.meta` fetch each, no re-download).
    In `LOCAL` fetch mode, the pre-downloaded archives (`nvdcpe-2.0.tar.gz` /
    `nvdcpematch-2.0.tar.gz`) must already exist under `--temp-dir`; unlike
    `API` mode they are not deleted afterwards.
  - Each `.tar.gz` contains multiple `*-chunk-NNNNN.json` files, each itself a
    complete page-shaped JSON payload (`{"products": [...]}` or
    `{"matchStrings": [...]}`) — parsed one chunk at a time via
    `_iter_archive_json_chunks` (keeps peak memory bounded to one ~50MB chunk
    rather than loading the full multi-GB uncompressed feed at once).
- Known caveats in the current implementation (not yet fixed, be aware when
  touching this code):
  - `LOCAL` fetch-mode's freshness timestamp is generated fresh every run
    (`_get_meta_date`), so `_is_feed_up_to_date` never matches a prior run —
    every `LOCAL` run always re-downloads-from-temp-dir/re-parses every year.
  - `cves` uses `INSERT OR IGNORE` on `cve_id` — an existing CVE's score/
    description/etc. is never updated on rerun, only genuinely new CVE ids
    get inserted.
  - EPSS `score_date` freshness parsing (`_load_epss_data_base`) truncates to
    the hour (`split(':')` on a value containing multiple colons) — only
    affects the freshness dedup check, not the actual EPSS scores/percentiles.
- Schema created by `--init` (`DataBaseManager._init_database_models`):
  - `cves` — one row per CVE, single "primary" CVSS metric only (see
    `_parse_metrics`). Columns: `cve_id, base_cvss_score, vector, version,
    severity, description, has_kev, epss_score, epss_percentile,
    published_date, exploit_date, references_count, weaknesses_count`.
  - `nvd_meta` — per-year (or `"EPSS"`) sync freshness metadata (dual-purpose:
    also stores the EPSS sync's `lastModifiedDate` under `year='EPSS'`).
  - `metadata` — single `last_update_date` key/value row.
  - `cpe_matches` — one row per `cpeMatch` entry found in each CVE's
    `configurations` block (vendor/product parsed out of `criteria` for
    indexed lookup, plus version range bounds); backs `search_cves_by_cpe`.
    Rows for a given `cve_id` are deleted and re-inserted on every parse of
    that CVE (idempotent even given the `LOCAL` reprocessing caveat above).
  - `cpe_dictionary` — one row per official NVD CPE name (only populated by
    `--init`); backs `resolve_cpe`.
  - `cpe_match_resolutions` — one row per concrete CPE that NVD resolved a
    given `matchCriteriaId` to (only populated by `--init`); backs
    `search_cves_by_cpe`'s `"exact"` match path (joined via `cpe_matches.
    match_criteria_id`). Rows for a given `matchCriteriaId` are deleted and
    re-inserted on every parse (idempotent, same rationale as `cpe_matches`).

## Code layout

- `src/vulnerability-mcp-server.py` — MCP entrypoint; registers tools with `@mcp.tool()`.
- `src/models/vulnerability.py` — `Vulnerability` data model (plain attribute bag,
  no validation); `render_mcp()` formats the string returned to MCP clients,
  `to_dict()`/`__repr__()` are for other uses.
- `src/models/config.py` — `DatabaseManagementConfig` dataclass for the
  `vuln-db` CLI args (`init_db`, `temp_directory`, `fetch_mode`).
- `src/cli/db.py` — `vuln-db` console-script entrypoint (registered via
  `pyproject.toml` `project.scripts`); parses CLI args into
  `DatabaseManagementConfig` and delegates to `DataBaseManager.load_data()`.
- `src/tools/database_clients.py` — module-level `SQLITE_MAX_VARIABLES` (500)
  + `_chunked()` helper: any `WHERE x IN (?, ?, ...)` query built from a list
  (caller-supplied `cve_ids`, or feed-derived `matchCriteriaId`s) MUST batch
  through `_chunked()` — SQLite's `SQLITE_MAX_VARIABLE_NUMBER` varies by build
  (999 on many systems, up to 32766 on others) and large NVD feed chunks can
  easily contain tens of thousands of distinct ids in one go. Two classes:
  - `DatabaseClient` (read side, used by the MCP server tools) opens a
    `sqlite3` connection in `__init__`; each `@mcp.tool()` creates its own
    short-lived instance (no shared/pooled connection). `fetch_data` queries
    `cves` by `cve_id` and mutates the passed-in `Vulnerability` in place
    (`epss_score`/`epss_percentile` converted to percentages ×100 here);
    `fetch_batch_data` does the same for a batch via `Vulnerability.to_dict()`.
    `fetch_epss_scores`/`fetch_kev_status`/`fetch_nvd_sync_status`/
    `search_cves_by_keyword`/`search_cves_by_cpe`/`resolve_cpe` instead
    take/return plain dicts/lists — `fetch_epss_scores` intentionally returns
    the DB's raw 0-1 fractions, NOT the ×100 percentages `fetch_data`
    produces. CPE matching helpers (`_parse_cpe_string`, `_version_matches`,
    `_version_sort_key`, `_get_resolved_versions`, etc.) are static/self
    -contained, no external version-comparison dependency.
  - `DataBaseManager` (write side, used by the `vuln-db` CLI) builds/refreshes
    the DB from live NVD/EPSS/CPE bulk feeds (or local files in `LOCAL` fetch
    mode) — see "Building/refreshing the database" above for details/caveats.
- `src/tools/logger.py` — `CLILogger` wraps stdlib `logging` with colorama;
  use `.trace/.success/.fail/.warning` rather than adding new logging setup.
- Imports inside `src/` use bare module paths (`from tools.x import y`, not
  `from src.tools...`) — this only works because Python adds the script's own
  directory to `sys.path` when run as `python src/vulnerability-mcp-server.py`,
  or because `pip install -e .` (`pyproject.toml`, `where = ["src"]`) puts
  `src/` packages (`cli`, `models`, `tools`) directly on `sys.path` for the
  `vuln-db` console script. Don't `cd` into `src/` and run things from there
  expecting relative DB paths to still work.

## Testing the server end-to-end

- Use `npx @modelcontextprotocol/inspector` (needs Node/npm) as a manual MCP
  client: add a `streamable-http` server pointing at `http://localhost:8000/mcp`.
- `opencode.json` at repo root registers this same server under the name
  `vulnerability-mcp` for use from OpenCode sessions directly — the server
  must already be running on port 8000 for that MCP connection to succeed.
