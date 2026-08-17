"""
REST API exposition for the vulnerability data source.

This module exposes the same vulnerability data as the MCP tools
(`vulnerability-mcp-server.py`), but as a plain JSON/REST API using FastAPI,
for clients that don't speak the MCP protocol. Both exposition layers share
the same business logic via `tools.vulnerability_service`, so behaviour is
identical between the two modes.

All data is served locally from the pre-loaded SQLite database (no outbound
network calls, no API key required).

Routes are defined on an `APIRouter` (not directly on a `FastAPI` app)
because the URL prefix they're mounted under is only known at launch time
(the `--path`/`path` config, resolved by `server.py`, mirroring MCP mode's
own mount path). Use `build_app(prefix)` to get a ready-to-serve app; the
module-level `app` below is a prefix-less convenience instance for direct
`uvicorn rest_api:app` usage / ad-hoc testing.
"""

from fastapi import APIRouter, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from tools import vulnerability_service as service

router = APIRouter()


class CveIdsRequest(BaseModel):
    """Request body for endpoints accepting a batch of CVE ids."""

    cve_ids: list[str] = Field(..., description="List of CVE ids, e.g. ['CVE-2025-53770']")


@router.get("/health", tags=["meta"], summary="Liveness check")
def health() -> dict:
    """Simple liveness check."""
    return {"status": "ok"}


@router.post("/epss-scores", tags=["cves"], summary="Get EPSS scores")
def get_epss_score(body: CveIdsRequest) -> dict:
    """Return EPSS score and percentile (0-1 fractions) for a list of CVE ids."""
    return service.get_epss_score(body.cve_ids)


@router.post("/kev-status", tags=["cves"], summary="Check CISA KEV status")
def check_kev_status(body: CveIdsRequest) -> dict:
    """Return whether each CVE id is listed in the CISA KEV catalog.

    Only the boolean membership flag is available (no date_added or
    known_ransomware_use, which would require syncing the live CISA feed).
    """
    return service.check_kev_status(body.cve_ids)


@router.get("/nvd-sync-status", tags=["meta"], summary="Get local NVD data freshness")
def get_nvd_sync_status() -> dict:
    """Return the freshness of the local NVD-derived data (last update date
    and per-year sync metadata), to help decide if a DB refresh is needed."""
    return service.get_nvd_sync_status()


# NOTE: route ordering matters in FastAPI/Starlette - static path segments
# (/cves/batch, /cves/search, /cves/search-by-cpe) must be declared BEFORE
# the dynamic /cves/{cve_id} route below, otherwise they would incorrectly
# be matched as `cve_id="batch"`/`"search"`/`"search-by-cpe"`.
@router.post("/cves/batch", tags=["cves"], summary="Batch get CVEs by id")
def batch_search_cves(body: CveIdsRequest) -> dict:
    """Return full CVE detail for a batch of CVE ids in a single call.

    Returns a dict per CVE id with the raw fields (cvss score, severity,
    epss, kev, etc.) plus a "found" flag for ids not present locally.
    """
    return service.batch_search_cves(body.cve_ids)


@router.get("/cves/search", tags=["cves"], summary="Search CVEs by keyword")
def search_cves_by_keyword(
    keyword: str = Query(..., description="Substring to search for in CVE descriptions"),
    limit: int = Query(50, ge=1, le=500),
) -> list:
    """Search CVEs whose description contains the given keyword (substring match).

    Results are ordered by CVSS base score (descending) and capped at `limit`
    (default 50).
    """
    return service.search_cves_by_keyword(keyword, limit)


@router.get("/cves/search-by-cpe", tags=["cves"], summary="Search CVEs by CPE")
def search_cves_by_cpe(
    cpe: str = Query(..., description="CPE 2.3 string, full or partial, e.g. 'cpe:2.3:a:apache:http_server'"),
    limit: int = Query(50, ge=1, le=500),
) -> list:
    """Search CVEs affecting a given CPE 2.3 string.

    Vendor/product are matched exactly. For the version, each result reports
    a `match_precision`: "exact" if resolved via NVD's own CPE Match Criteria
    feed (requires `vuln-db --init` to have been run), otherwise
    "approximate".
    """
    return service.search_cves_by_cpe(cpe, limit)


@router.get("/cves/{cve_id}", tags=["cves"], summary="Get CVE by id")
def get_cve_by_id(cve_id: str) -> dict:
    """Return the full detail of a single CVE, given its CVE id."""
    vulnerability = service.get_cve_by_id(cve_id)
    if vulnerability.published_date is None:
        raise HTTPException(status_code=404, detail=f"CVE '{cve_id}' not found")
    return vulnerability.to_dict()


@router.get("/cpe/resolve", tags=["cpe"], summary="Resolve CPE names by keyword")
def resolve_cpe(
    keyword: str = Query(..., description="Keyword to search in the CPE dictionary"),
    limit: int = Query(50, ge=1, le=500),
) -> list:
    """Search the local CPE dictionary (vendor/product/title) for entries
    matching a keyword, e.g. to find the exact CPE name for a product before
    calling /cves/search-by-cpe.

    Requires the CPE dictionary to have been synced locally first via
    `vuln-db --init`. Returns an empty list if not synced yet.
    """
    return service.resolve_cpe(keyword, limit)


def normalize_prefix(prefix: "str | None") -> str:
    """Normalizes a URL prefix: '', None, '/' or 'nvd-mcp'/'/nvd-mcp/' all
    become either '' (no prefix, mount at root) or a leading-slash,
    no-trailing-slash form (e.g. '/nvd-mcp'), as required by
    `APIRouter(prefix=...)`."""
    if not prefix or prefix == "/":
        return ""
    return "/" + prefix.strip("/")


def build_app(prefix: "str | None" = "") -> FastAPI:
    """Builds the REST FastAPI app, with all routes mounted under `prefix`
    (e.g. `/api`). An empty/None/`/` prefix mounts routes at the root.

    Note: FastAPI's own built-in routes (`/docs`, `/redoc`, `/openapi.json`)
    are NOT affected by `prefix` and always stay at the app root.
    """
    rest_app = FastAPI(
        title="Vulnerability Data Source - REST API",
        description=(
            "REST equivalent of the Vulnerability Data Source MCP server. "
            "All data is served locally from the pre-loaded SQLite database "
            "(no outbound network calls, no API key required)."
        ),
        version="1.0.0",
    )
    rest_app.include_router(router, prefix=normalize_prefix(prefix))
    return rest_app


# Prefix-less convenience instance, e.g. for `uvicorn rest_api:app` or ad-hoc
# testing. `vuln-server --mode rest` does NOT use this: it calls
# `build_app(config.path)` directly, see `server.py`.
app = build_app()
