"""
Database clients for fetching vulnerability data from database with pre-loaded data .

This module provides classes to interact with the database, fetching details such as CVSS scores,
EPSS scores, and KEV status for vulnerabilities.
"""

import sqlite3
import datetime
import os
import csv
import gzip
import json
import re
import tarfile
from io import StringIO,BytesIO
from colorama import Fore,Style
import requests
from models.vulnerability import Vulnerability
from tools.logger import CLILogger

# SQLite's default SQLITE_MAX_VARIABLE_NUMBER varies by build (999 on older/
# many system SQLite versions, 32766 since SQLite 3.32.0 on others). Any query
# using a `WHERE x IN (?, ?, ...)` clause built from a caller-supplied or
# feed-derived list must stay well under the lowest common value to avoid
# "too many SQL variables" (sqlite3.OperationalError).
SQLITE_MAX_VARIABLES = 500


def _chunked(items, size):
    """Yields successive `size`-sized chunks from `items` (accepts any iterable)."""
    items = list(items)
    for index in range(0, len(items), size):
        yield items[index:index + size]


class DatabaseClient():
    """
    Client for fetching vulnerability data from the NVD API.

    Attributes:
        conn: SQLite database connection.
        cur: Database cursor.
    """

    def __init__(self, db_path: str):
        self.logger = CLILogger("DatabaseClient")
        self.conn = sqlite3.connect(db_path)
        self.cur = self.conn.cursor()

    def fetch_last_update_date(self):
        """
        Fetches last update date from database
        """
        return self._fetch_metadta("last_update_date")

    def _fetch_metadta(self,key:str):
        self.cur.execute("""
            SELECT value FROM metadata WHERE key = ?
        """, (key,))
        return self.cur.fetchone()[0]

    _CVE_ROW_COLUMNS = (
        "cve_id, base_cvss_score, vector, version, severity, description, has_kev,"
        "epss_score,epss_percentile,published_date,exploit_date,references_count,weaknesses_count,weaknesses"
    )

    def fetch_data(self, vulnerability: Vulnerability):
        """
        Fetches data from the databse and populates the vulnerability object.
        Args:
            vulnerability: Vulnerability object to populate with API data.
        """
        self.logger.trace(f"Fetch {vulnerability.cve_id}: START")
        self.cur.execute(f"""
            SELECT {self._CVE_ROW_COLUMNS}
            FROM cves
            WHERE cve_id = ?
        """, (vulnerability.cve_id,))
        result = self.cur.fetchone()
        if result:
            self._populate_from_row(vulnerability, result)
            self.logger.success(f"Fetch {vulnerability.cve_id}","DONE")
        else:
            self.logger.fail(f"Fetch {vulnerability.cve_id}","NOT FOUND")

    def _populate_from_row(self, vulnerability: Vulnerability, result: tuple) -> None:
        """Maps a `cves` row (see `_CVE_ROW_COLUMNS` for column order) onto a Vulnerability."""
        vulnerability.base_cvss_score = result[1]
        vulnerability.cvss_score = result[1]
        vulnerability.vector = result[2]
        vulnerability.version = result[3]
        vulnerability.severity = result[4]
        vulnerability.description = result[5]
        vulnerability.has_kev = bool(result[6])
        vulnerability.epss_score = result[7]
        vulnerability.epss_percentile = result[8]
        vulnerability.published_date = result[9]
        vulnerability.exploit_date = result[10]
        vulnerability.references_count = result[11]
        vulnerability.weaknesses_count = result[12]
        vulnerability.weaknesses = result[13]

    def fetch_batch_data(self, cve_ids: list[str]) -> dict:
        """
        Fetches full CVE details for a batch of CVE ids in a single query.

        Args:
            cve_ids: List of CVE ids to look up.

        Returns:
            dict: mapping cve_id -> Vulnerability.to_dict() (with an extra
            "found" key), or {"id": cve_id, "found": False} for CVE ids not
            present in the database.
        """
        self.logger.trace(f"Batch fetch {len(cve_ids)} CVE(s): START")
        result_map = {cve_id: {"id": cve_id, "found": False} for cve_id in cve_ids}
        if not cve_ids:
            return result_map

        for batch in _chunked(cve_ids, SQLITE_MAX_VARIABLES):
            placeholders = ",".join("?" for _ in batch)
            self.cur.execute(
                f"SELECT {self._CVE_ROW_COLUMNS} FROM cves WHERE cve_id IN ({placeholders})",
                batch,
            )
            for row in self.cur.fetchall():
                vulnerability = Vulnerability(row[0], "", "")
                self._populate_from_row(vulnerability, row)
                entry = vulnerability.to_dict()
                entry["found"] = True
                result_map[row[0]] = entry
        self.logger.success("Batch fetch CVE(s)", "DONE")
        return result_map

    def fetch_epss_scores(self, cve_ids: list[str]) -> dict:
        """
        Fetches EPSS score and percentile for a batch of CVE ids.

        Values are returned as stored in the database, i.e. fractions in the
        [0, 1] range (NOT converted to percentages, unlike `fetch_data`/
        `Vulnerability.render_mcp`).

        Args:
            cve_ids: List of CVE ids to look up.

        Returns:
            dict: mapping cve_id -> {"epss_score": float|None,
            "epss_percentile": float|None, "found": bool}.
        """
        self.logger.trace(f"Fetch EPSS scores for {len(cve_ids)} CVE(s): START")
        result_map = {cve_id: {"epss_score": None, "epss_percentile": None, "found": False} for cve_id in cve_ids}
        if not cve_ids:
            return result_map

        for batch in _chunked(cve_ids, SQLITE_MAX_VARIABLES):
            placeholders = ",".join("?" for _ in batch)
            self.cur.execute(
                f"SELECT cve_id, epss_score, epss_percentile FROM cves WHERE cve_id IN ({placeholders})",
                batch,
            )
            for cve_id, epss_score, epss_percentile in self.cur.fetchall():
                result_map[cve_id] = {
                    "epss_score": epss_score,
                    "epss_percentile": epss_percentile,
                    "found": True,
                }
        self.logger.success("Fetch EPSS scores", "DONE")
        return result_map

    def fetch_kev_status(self, cve_ids: list[str]) -> dict:
        """
        Fetches CISA KEV membership for a batch of CVE ids.

        Only the boolean flag stored locally (`has_kev`) is available; the
        local database does not store `date_added` or `known_ransomware_use`
        (these would require syncing the live CISA KEV feed).

        Args:
            cve_ids: List of CVE ids to look up.

        Returns:
            dict: mapping cve_id -> {"in_kev": bool|None, "found": bool}.
            "in_kev" is None when the CVE id is not found in the database.
        """
        self.logger.trace(f"Fetch KEV status for {len(cve_ids)} CVE(s): START")
        result_map = {cve_id: {"in_kev": None, "found": False} for cve_id in cve_ids}
        if not cve_ids:
            return result_map

        for batch in _chunked(cve_ids, SQLITE_MAX_VARIABLES):
            placeholders = ",".join("?" for _ in batch)
            self.cur.execute(
                f"SELECT cve_id, has_kev FROM cves WHERE cve_id IN ({placeholders})",
                batch,
            )
            for cve_id, has_kev in self.cur.fetchall():
                result_map[cve_id] = {"in_kev": bool(has_kev), "found": True}
        self.logger.success("Fetch KEV status", "DONE")
        return result_map

    def fetch_nvd_sync_status(self) -> dict:
        """
        Fetches local NVD data freshness metadata.

        Reads the `metadata` and `nvd_meta` tables that are populated at
        database build time but not otherwise queried by the application.

        Returns:
            dict: {"last_update_date": str|None, "years": [
                {"year": str, "last_modified_date": str, "size": int,
                "zip_size": int, "gz_size": int, "sha256": str}, ...
            ]}
        """
        self.logger.trace("Fetch NVD sync status: START")
        self.cur.execute("SELECT value FROM metadata WHERE key = 'last_update_date'")
        row = self.cur.fetchone()
        last_update_date = row[0] if row else None

        self.cur.execute(
            "SELECT year, lastModifiedDate, size, zipSize, gzSize, sha256 FROM nvd_meta ORDER BY year"
        )
        years = [
            {
                "year": year,
                "last_modified_date": last_modified_date,
                "size": size,
                "zip_size": zip_size,
                "gz_size": gz_size,
                "sha256": sha256,
            }
            for year, last_modified_date, size, zip_size, gz_size, sha256 in self.cur.fetchall()
        ]
        self.logger.success("Fetch NVD sync status", "DONE")
        return {"last_update_date": last_update_date, "years": years}

    def search_cves_by_keyword(self, keyword: str, limit: int = 50) -> list:
        """
        Searches CVEs whose description contains the given keyword (case-insensitive
        substring match via SQL LIKE).

        Args:
            keyword: Text to search for in the CVE description.
            limit: Maximum number of results to return (default 50).

        Returns:
            list[dict]: matching CVEs, each with cve_id, base_cvss_score, severity,
            has_kev, published_date and description, ordered by CVSS score (desc).
        """
        self.logger.trace(f"Search CVEs by keyword '{keyword}': START")
        if not keyword or not keyword.strip():
            return []

        self.cur.execute(
            """
            SELECT cve_id, base_cvss_score, severity, has_kev, published_date, description,weaknesses
            FROM cves
            WHERE description LIKE ? ESCAPE '\\'
            ORDER BY base_cvss_score DESC
            LIMIT ?
            """,
            (f"%{self._escape_like(keyword)}%", limit),
        )
        results = [
            {
                "cve_id": row[0],
                "base_cvss_score": row[1],
                "severity": row[2],
                "has_kev": bool(row[3]),
                "published_date": row[4],
                "weaknesses": row[6],
                "description": row[5],
            }
            for row in self.cur.fetchall()
        ]
        self.logger.success(f"Search CVEs by keyword '{keyword}'", f"{len(results)} result(s)")
        return results

    @staticmethod
    def _escape_like(value: str) -> str:
        """Escapes SQL LIKE wildcard characters (`%`, `_`, `\\`) in user input."""
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    def _table_exists(self, table_name: str) -> bool:
        self.cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name = ?", (table_name,)
        )
        return self.cur.fetchone() is not None

    def search_cves_by_cpe(self, cpe: str, limit: int = 50) -> list:
        """
        Searches CVEs affecting a given CPE 2.3 string.

        Matching is exact vendor/product, plus for the version component:
        - If `cpe_match_resolutions` has been synced (`vuln-db --init`)
          and covers this criteria's matchCriteriaId, the version is checked
          against NVD's own resolved list of concrete matching CPEs
          (`match_precision: "exact"` in the result).
        - Otherwise, falls back to an approximate numeric/lexicographic
          comparison against the stored version range bounds from NVD
          `configurations` (`match_precision: "approximate"`); escaped
          characters or unusual version schemes may not resolve correctly.

        Args:
            cpe: A CPE 2.3 string, e.g. 'cpe:2.3:a:apache:http_server:2.4.49'.
                 Trailing components may be omitted (treated as wildcards).
            limit: Maximum number of results to return (default 50).

        Returns:
            list[dict]: matching CVEs with cve_id, matched_criteria, match_precision,
            base_cvss_score, severity, has_kev, published_date, description.
        """
        self.logger.trace(f"Search CVEs by CPE '{cpe}': START")
        if not self._table_exists("cpe_matches"):
            self.logger.warning("cpe_matches table not found - run `vuln-db --init` to migrate the schema")
            return []

        components = self._parse_cpe_string(cpe)
        if components is None:
            self.logger.fail(f"Search CVEs by CPE '{cpe}'", "INVALID CPE FORMAT")
            return []
        
        self.cur.execute(
            """
            SELECT DISTINCT m.cve_id, m.criteria, m.match_criteria_id,
                   m.version_start_including, m.version_start_excluding,
                   m.version_end_including, m.version_end_excluding,
                   c.base_cvss_score, c.severity, c.has_kev, c.published_date, c.description,c.weaknesses
            FROM cpe_matches m
            JOIN cves c ON c.cve_id = m.cve_id
            WHERE m.vendor = ? AND m.product = ?
            """,
            (components["vendor"], components["product"]),
        )
        rows = self.cur.fetchall()
        has_resolutions_table = self._table_exists("cpe_match_resolutions")
        requested_version = components["version"]
        resolution_cache = {}

        results = []
        seen_cve_ids = set()
        for row in rows:
            (cve_id, criteria, match_criteria_id, start_incl, start_excl, end_incl, end_excl,
             base_score, severity, has_kev, published_date, description,weaknesses) = row
            if cve_id in seen_cve_ids:
                continue

            if requested_version in (None, "", "*"):
                is_match, match_precision = True, "exact"
            else:
                resolved_versions = None
                if has_resolutions_table and match_criteria_id:
                    if match_criteria_id not in resolution_cache:
                        resolution_cache[match_criteria_id] = self._get_resolved_versions(match_criteria_id)
                    resolved_versions = resolution_cache[match_criteria_id]
                if resolved_versions is not None:
                    is_match, match_precision = requested_version in resolved_versions, "exact"
                else:
                    criteria_version = self._extract_cpe_component(criteria, 5)
                    is_match = self._version_matches(
                        requested_version, criteria_version, start_incl, start_excl, end_incl, end_excl
                    )
                    match_precision = "approximate"

            if is_match:
                seen_cve_ids.add(cve_id)
                results.append({
                    "cve_id": cve_id,
                    "matched_criteria": criteria,
                    "match_precision": match_precision,
                    "base_cvss_score": base_score,
                    "severity": severity,
                    "has_kev": bool(has_kev),
                    "published_date": published_date,
                    "weaknesses": weaknesses,
                    "description": description,
                })
                if len(results) >= limit:
                    break
        self.logger.success(f"Search CVEs by CPE '{cpe}'", f"{len(results)} result(s)")
        return results

    def _get_resolved_versions(self, match_criteria_id: str) -> "set | None":
        """Looks up the exact resolved CPE versions for a matchCriteriaId in
        `cpe_match_resolutions` (populated by `vuln-db --init`).

        Returns None if no resolution rows exist for this id (not synced, or
        NVD resolved zero concrete CPEs for it) so the caller can fall back to
        the approximate version-range comparison.
        """
        self.cur.execute(
            "SELECT cpe_name FROM cpe_match_resolutions WHERE match_criteria_id = ?",
            (match_criteria_id,),
        )
        rows = self.cur.fetchall()
        if not rows:
            return None
        return {self._extract_cpe_component(row[0], 5) for row in rows}

    def resolve_cpe(self, keyword: str, limit: int = 50) -> list:
        """
        Searches the local CPE dictionary (synced via `vuln-db --init`) for
        entries whose vendor, product or title matches the given keyword.

        Args:
            keyword: Text to search for.
            limit: Maximum number of results to return (default 50).

        Returns:
            list[dict]: matching CPE entries (cpe_name, vendor, product, version,
            title, deprecated), or an empty list if the dictionary hasn't been
            synced locally yet.
        """
        self.logger.trace(f"Resolve CPE for keyword '{keyword}': START")
        if not keyword or not keyword.strip():
            return []
        if not self._table_exists("cpe_dictionary"):
            self.logger.warning("cpe_dictionary table not found - run `vuln-db --init` first")
            return []

        like_value = f"%{self._escape_like(keyword)}%"
        self.cur.execute(
            """
            SELECT cpe_name, vendor, product, version, title, deprecated
            FROM cpe_dictionary
            WHERE vendor LIKE ? ESCAPE '\\' OR product LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\'
            ORDER BY deprecated ASC, product ASC
            LIMIT ?
            """,
            (like_value, like_value, like_value, limit),
        )
        results = [
            {
                "cpe_name": row[0],
                "vendor": row[1],
                "product": row[2],
                "version": row[3],
                "title": row[4],
                "deprecated": bool(row[5]),
            }
            for row in self.cur.fetchall()
        ]
        self.logger.success(f"Resolve CPE for keyword '{keyword}'", f"{len(results)} result(s)")
        return results

    @staticmethod
    def _split_cpe(cpe_string: str) -> list:
        """Splits a CPE 2.3 string into its components.

        Does not handle backslash-escaped colons within a component (rare in
        practice); good enough for vendor/product/version-level matching.
        """
        return cpe_string.strip().split(":")

    def _parse_cpe_string(self, cpe: str) -> dict | None:
        """Parses a (possibly partial) CPE 2.3 string into part/vendor/product/version.

        Missing trailing components default to '*' (wildcard). Returns None if
        the string doesn't look like a CPE 2.3 string at all.
        """
        parts = self._split_cpe(cpe)
        if len(parts) < 4 or parts[0] != "cpe" or parts[1] != "2.3":
            return None

        def part_at(index: int) -> str:
            return parts[index] if index < len(parts) and parts[index] else "*"

        return {
            "part": part_at(2),
            "vendor": part_at(3),
            "product": part_at(4),
            "version": part_at(5),
        }

    @classmethod
    def _extract_cpe_component(cls, cpe_string: str, index: int) -> str:
        """Extracts a single positional component from a CPE 2.3 string (e.g. index
        5 = version), defaulting to '*' if absent."""
        if not cpe_string:
            return "*"
        parts = cls._split_cpe(cpe_string)
        value = parts[index] if index < len(parts) else "*"
        return value if value else "*"

    def _version_matches(
        self, requested_version: str, criteria_version: str,
        start_incl: str, start_excl: str, end_incl: str, end_excl: str,
    ) -> bool:
        """Checks whether `requested_version` satisfies a stored match criteria."""
        if requested_version in (None, "", "*"):
            return True
        if criteria_version not in (None, "", "*", "-") and criteria_version == requested_version:
            return True
        if any([start_incl, start_excl, end_incl, end_excl]):
            return self._version_in_range(requested_version, start_incl, start_excl, end_incl, end_excl)
        # No version range on this criteria: only a wildcard version criteria matches.
        return criteria_version in (None, "", "*")

    def _version_in_range(
        self, version: str, start_incl: str, start_excl: str, end_incl: str, end_excl: str,
    ) -> bool:
        """Best-effort numeric/lexicographic version range comparison (no external deps)."""
        try:
            value = self._version_sort_key(version)
            if start_incl and value < self._version_sort_key(start_incl):
                return False
            if start_excl and value <= self._version_sort_key(start_excl):
                return False
            if end_incl and value > self._version_sort_key(end_incl):
                return False
            if end_excl and value >= self._version_sort_key(end_excl):
                return False
            return True
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _version_sort_key(version: str) -> list:
        """Turns a version string (e.g. '2.4.49') into a comparable list of
        (kind, value) tuples so numeric segments compare numerically and
        non-numeric segments compare lexicographically."""
        segments = [segment for segment in re.split(r"[._\-+]", version) if segment != ""]
        return [(0, int(segment)) if segment.isdigit() else (1, segment) for segment in segments]

    def close(self):
        """Closes the databse connection if it is open."""
        self.conn.close()


class DataBaseManager:
    """
    Manages the loading and updating of vulnerability data in the database.

    Attributes:
        NVD_FEEDS_START: The first year of NVD feeds to load.
        TIMEOUT: Timeout for HTTP requests in seconds.
    """

    NVD_FEEDS_START = 2002
    TIMEOUT = 10
    # Larger feed downloads (CPE dictionary/match, hundreds of MB) get a more
    # forgiving per-read timeout while keeping the same connect timeout.
    FEED_DOWNLOAD_TIMEOUT = (TIMEOUT, 60)
    CPE_DICTIONARY_META_URL = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.meta"
    CPE_DICTIONARY_FEED_URL = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz"
    CPE_MATCH_META_URL = "https://nvd.nist.gov/feeds/json/cpematch/2.0/nvdcpematch-2.0.meta"
    CPE_MATCH_FEED_URL = "https://nvd.nist.gov/feeds/json/cpematch/2.0/nvdcpematch-2.0.tar.gz"

    def __init__(self, database_path: str, temporary_directory: str,fetch_mode:str):
        """Initialize the database manager with paths and connection."""
        self.logger = CLILogger("DataBaseManager")
        self.database_path = database_path
        self.temporary_directory = temporary_directory
        self.fetch_mode = fetch_mode
        self.conn = sqlite3.connect(self.database_path)
        self.cursor = self.conn.cursor()



    def load_data(self,init_db:bool):
        """Loads and initializes all necessary data for vulnerability processing.

            Args:
                init_db (bool): If True, creates the database schema (if
                    missing) and fully populates it: in addition to the
                    regular NVD CVE/EPSS refresh (always run), this also syncs
                    the full CPE dictionary (`cpe_dictionary`, backs
                    `resolve_cpe`) and the CPE Match Criteria resolution feed
                    (`cpe_match_resolutions`, backs `search_cves_by_cpe`'s
                    exact matching) from their respective NVD bulk feeds.
                    These are large one-time downloads (~82MB and ~795MB
                    compressed respectively). `--init` also forces a full
                    re-download/re-parse of every year of the NVD CVE feed
                    (see `_load_nvd_data_base`'s `force` param) so that
                    `cpe_matches` gets (re)populated even for CVEs that were
                    already synced before this table existed - expect --init
                    to take noticeably longer than a regular refresh.
        """
        if init_db:
            self._init_database_models()
            self._load_cpe_dictionary()
            self._load_cpe_match_resolutions()
        self._load_nvd_data_base(force=init_db)
        self._load_epss_data_base()
        self._update_global_metdata()


    def _init_database_models(self):
        self.logger.trace("Database Creation: STARTED")
        print(f"[{self.__class__.__name__}] Create database {self.database_path}")
        conn = sqlite3.connect(self.database_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT UNIQUE,
                published_date TEXT,
                base_cvss_score REAL,
                vector TEXT,
                version TEXT,
                severity TEXT,
                description TEXT,
                has_kev INTEGER,
                exploit_date TEXT,
                epss_score REAL,
                epss_percentile REAL,
                references_count INTEGER,
                weaknesses_count INTEGER,
                weaknesses TEXT
                    
            );
        """)
        cur.execute('''
            CREATE TABLE IF NOT EXISTS nvd_meta (
                year TEXT,
                lastModifiedDate TEXT,
                size INTEGER,
                zipSize INTEGER,
                gzSize INTEGER,
                format TEXT,
                version TEXT,
                sha256 TEXT
            );
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            );
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS cpe_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                operator TEXT,
                negate INTEGER,
                vulnerable INTEGER,
                criteria TEXT,
                match_criteria_id TEXT,
                vendor TEXT,
                product TEXT,
                version_start_including TEXT,
                version_start_excluding TEXT,
                version_end_including TEXT,
                version_end_excluding TEXT
            );
        ''')
        cur.execute('''
            CREATE INDEX IF NOT EXISTS idx_cpe_matches_vendor_product
            ON cpe_matches(vendor, product);
        ''')
        cur.execute('''
            CREATE INDEX IF NOT EXISTS idx_cpe_matches_cve_id
            ON cpe_matches(cve_id);
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS cpe_dictionary (
                cpe_name_id TEXT PRIMARY KEY,
                cpe_name TEXT,
                part TEXT,
                vendor TEXT,
                product TEXT,
                version TEXT,
                title TEXT,
                deprecated INTEGER,
                last_modified TEXT,
                created TEXT
            );
        ''')
        cur.execute('''
            CREATE INDEX IF NOT EXISTS idx_cpe_dictionary_vendor_product
            ON cpe_dictionary(vendor, product);
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS cpe_match_resolutions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                match_criteria_id TEXT,
                cpe_name TEXT,
                cpe_name_id TEXT
            );
        ''')
        cur.execute('''
            CREATE INDEX IF NOT EXISTS idx_cpe_match_resolutions_criteria_id
            ON cpe_match_resolutions(match_criteria_id);
        ''')
        conn.commit()
        conn.close()
        self.logger.success("Database Creation","DONE")

    def _get_meta_date(self):
        iso_time = datetime.datetime.now().isoformat()
        return iso_time

    def _load_nvd_data_base(self, force: bool = False) -> None:
        """Load NVD data for each year from the start year to the current year.

        Args:
            force: If True, ignore the per-year freshness check and always
                re-download + re-parse every year. Needed for `--init`:
                `cpe_matches` is only populated as a side effect of parsing
                each year's raw CVE JSON (`_parse_configurations`), so a year
                already marked up-to-date in `nvd_meta` from a previous sync
                (before `cpe_matches` existed, or before `--init` was last
                run) would otherwise never be re-parsed, silently leaving
                `cpe_matches` empty/incomplete even though `cves` looks fully
                populated.
        """
        today = datetime.date.today()
        for year in range(self.NVD_FEEDS_START, today.year+1):
            if self.fetch_mode == 'API':
                meta_file_url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.meta"
                response = requests.get(meta_file_url,timeout=self.TIMEOUT)
                meta_data = self._parse_nvd_meta_data(response.text)
                last_modified_date = meta_data.get("lastModifiedDate")
            else:
                last_modified_date = self._get_meta_date()
                meta_data = {'lastModifiedDate': last_modified_date}
            if force or not self._is_feed_up_to_date(str(last_modified_date),str(year)):
                self._save_nvd_meta_data(meta_data, str(year))
                self._download_and_parse_nvd_file(str(year))
                self.conn.commit()
            else:
                self.logger.trace(f"Vulnerabilities {str(year)} up-to-date")


    def _parse_nvd_meta_data(self, meta_content: str) -> dict[str, str]:
        """Parse the meta data from the NVD feed."""
        meta_data = {}
        for line in StringIO(meta_content):
            if ":" in line:
                key, value = line.strip().split(":", 1)
                meta_data[key.strip()] = value.strip()
        return meta_data

    def _save_nvd_meta_data(self, meta_data: dict[str, str], year: str) -> None:
        """Save the meta data to the database."""
        self.cursor.execute(
            """
            INSERT INTO nvd_meta (year, lastModifiedDate, size, zipSize, gzSize, sha256)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                year,
                meta_data.get("lastModifiedDate"),
                int(meta_data.get("size", 0)),
                int(meta_data.get("zipSize", 0)),
                int(meta_data.get("gzSize", 0)),
                meta_data.get("sha256"),
            ),
        )

    def _download_and_parse_nvd_file(self,year:str) -> None:
        if self.fetch_mode == 'API':
            file_url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
            self.logger.trace(f" Downloading {file_url}")
            response = requests.get(file_url, timeout=self.TIMEOUT)

        if self.fetch_mode == 'LOCAL' or response.status_code == 200:
            self.logger.success(f"Download nvdcve-2.0-{year}.json.gz","DONE")
            file_name =  f"nvdcve-2.0-{year}.json"
            json_path = os.path.join(self.temporary_directory,file_name)
            data = open(os.path.join(self.temporary_directory, f"{file_name}.gz"),'rb') if self.fetch_mode == 'LOCAL' else BytesIO(response.content)
            with gzip.GzipFile(fileobj=data, mode='rb') as gz_file:
                with open(json_path, "wb") as json_file:
                    json_file.write(gz_file.read())
            self.logger.trace(f"Saved to {json_path}")
            self._parse_nvd_file(json_path)
            os.remove(json_path)
        else:
            self.logger.fail(f"Download nvdcve-2.0-{year}.json.gz failed status code",f" {response.status_code}")





    def _parse_nvd_file(self,file_path:str):
        """Parse the NVD JSON file and insert data into the database."""
        self.logger.trace(f"Parse {file_path}")
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            vulnerabilities = data.get("vulnerabilities",[])
            if not vulnerabilities:
                print(f"[{self.__class__.__name__}]  No vulnerabilities data for {file_path}.")
                return
            for item in vulnerabilities:
                cve_data = item.get("cve")
                if cve_data:
                    cve_entries = self._extract_cve_entries(cve_data)
                    self.cursor.executemany("""
                        INSERT OR IGNORE INTO cves (
                            cve_id,published_date, base_cvss_score, vector, version, severity, description, has_kev,exploit_date,references_count,weaknesses_count,weaknesses
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)
                    """, [cve_entries])
                    self._parse_configurations(cve_data.get("id"), cve_data.get("configurations", []))

    def _parse_configurations(self, cve_id: str, configurations: list) -> None:
        """Extracts CPE match criteria from a CVE's `configurations` block and
        stores one row per cpeMatch entry in `cpe_matches` (used by
        `search_cves_by_cpe`).

        Deletes any previously stored rows for this cve_id first, so re-parsing
        the same CVE (e.g. LOCAL fetch mode always reprocessing feed files) does
        not accumulate duplicate rows.
        """
        if not cve_id:
            return
        self.cursor.execute("DELETE FROM cpe_matches WHERE cve_id = ?", (cve_id,))
        if not configurations:
            return
        rows = []
        for configuration in configurations:
            for node in configuration.get("nodes", []):
                operator = node.get("operator")
                negate = 1 if node.get("negate") else 0
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria")
                    if not criteria:
                        continue
                    criteria_parts = criteria.split(":")
                    vendor = criteria_parts[3] if len(criteria_parts) > 3 else None
                    product = criteria_parts[4] if len(criteria_parts) > 4 else None
                    rows.append((
                        cve_id,
                        operator,
                        negate,
                        1 if cpe_match.get("vulnerable") else 0,
                        criteria,
                        cpe_match.get("matchCriteriaId"),
                        vendor,
                        product,
                        cpe_match.get("versionStartIncluding"),
                        cpe_match.get("versionStartExcluding"),
                        cpe_match.get("versionEndIncluding"),
                        cpe_match.get("versionEndExcluding"),
                    ))
        if rows:
            self.cursor.executemany("""
                INSERT INTO cpe_matches (
                    cve_id, operator, negate, vulnerable, criteria, match_criteria_id,
                    vendor, product, version_start_including, version_start_excluding,
                    version_end_including, version_end_excluding
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)

    def _extract_cve_entries(self, cve_data: dict) -> list:
        """Extract CVE entries from the CVE data."""
        cve_entries = [cve_data.get("id")]
        if cve_data.get("published") is not None:
            cve_entries.append(cve_data.get("published").split("T")[0]) # type: ignore
        else :
            cve_entries.append("")
        self._parse_metrics(cve_entries, cve_data.get("metrics", {}))
        self._parse_description(cve_entries, cve_data.get("descriptions", []))
        cve_entries.append(1 if cve_data.get("cisaExploitAdd") else 0)
        cve_entries.append(cve_data.get("cisaExploitAdd"))
        if cve_data.get("references"):
            cve_entries.append(len(cve_data.get("references"))) # type: ignore
        else:
            cve_entries.append("0")
        if cve_data.get("weaknesses"):
            self._parse_weaknesses(cve_entries,cve_data.get("weaknesses")) # type: ignore
        else:
            cve_entries.append("0")
            cve_entries.append("")
        return cve_entries

    def _parse_weaknesses(self, cve_entries: list, weaknesses: list[dict]) -> None:
        count_weaknesses = 0
        weaknessesData = ''
        for weakness_list in weaknesses:
            valid_descriptions = [desc for desc in weakness_list.get("description") if isinstance(desc, dict) and desc.get("value", "").startswith("CWE-")] # type: ignore
                
            for description in valid_descriptions:
                 weaknessesData += " "+description.get("value")
            weaknessesData = weaknessesData.strip()
            count_weaknesses = len(valid_descriptions)
                
        cve_entries.append(count_weaknesses)
        cve_entries.append(weaknessesData)


    def _parse_metrics(
        self, cve_entries: list, metrics: dict[str, dict]
    ) -> None:
        base_score = 0.0
        vector = ''
        version = ''
        severity = ''
        for metric_version in metrics:
            
            for metric in metrics[metric_version]:
                if metric.get("cvssData"):
                    cvss_data = metric.get("cvssData")
                    base_score = cvss_data.get("baseScore")
                    vector = cvss_data.get("vectorString")
                    version = cvss_data.get("version")
                    severity = cvss_data.get(
                        "baseSeverity", metric.get("baseSeverity")
                    )
                    if metric.get("type") == "Primary":
                        cve_entries.append(base_score)
                        cve_entries.append(vector)
                        cve_entries.append(version)
                        cve_entries.append(severity)
                        return
        cve_entries.append(base_score)
        cve_entries.append(vector)
        cve_entries.append(version)
        cve_entries.append(severity)

    def _parse_description(
        self, cve_entries: list, descriptions: list[dict[str, str]]
    ) -> None:
        for description in descriptions:
            if description.get("lang") == "en":
                cve_entries.append(description["value"])
                return
        cve_entries.append("")



    def _load_epss_data_base(self):
        epss_path = os.path.join(self.temporary_directory, "epss_scores-current.csv.gz")
        if self.fetch_mode == 'API':
            file_url = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
            self.logger.trace("EPSS data udpate STARTED")
            response = requests.get(file_url,timeout=self.TIMEOUT)
            if response.status_code == 200:
                epss_path = os.path.join(self.temporary_directory, "epss_scores-current.csv.gz")
                with open(epss_path, "wb") as f:
                    f.write(response.content)
                self.logger.success("Download EPSS data","DONE")
            else:
                self.logger.fail("Download EPSS data","FAIL")
        with gzip.open(epss_path, 'rt') as f:
            # Skip the first comment line
            first_line = f.readline()
            parts = first_line.split(',')
            score_date_part = parts[1].split(':')[1]
            if not self._is_feed_up_to_date(score_date_part,"EPSS"):
                self._save_epss_meta(score_date_part)
                if not first_line.startswith("#"):
                    f.seek(0)
                reader = csv.DictReader(f)
                for row in reader:
                    cve_id = row['cve'].strip()
                    epss = float(row['epss']) if row['epss'] else None
                    percentile = float(row['percentile']) if row['percentile'] else None
                    self.cursor.execute("""
                        UPDATE cves
                        SET epss_score = ?, epss_percentile = ?
                        WHERE cve_id = ?
                    """, (epss, percentile, cve_id))
                self.logger.success("EPSS data udpate","DONE")
            else:
                self.logger.trace("EPSS data up-to-date")
        self.conn.commit()
        if self.fetch_mode == 'API':
            os.remove(epss_path)


    def _save_epss_meta(self, score_date_part: str) -> None:
        """Save EPSS meta data to the database."""
        self.cursor.execute(
            """
            INSERT INTO nvd_meta (year, lastModifiedDate, size, zipSize, gzSize, sha256)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("EPSS", score_date_part, 0, 0, 0, ""),
        )


    def _is_feed_up_to_date(self,last_modified_date:str,year:str):
        self.cursor.execute('''
            SELECT lastModifiedDate FROM nvd_meta WHERE lastModifiedDate = ? and year = ?
        ''', (last_modified_date,year))
        return self.cursor.fetchone()

    def _update_global_metdata(self):
        now = datetime.datetime.now().replace(microsecond=0)
        formatted = now.isoformat(sep=' ')
        self.cursor.execute("""
            INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)
        """, ('last_update_date',formatted))
        self.conn.commit()

    def _fetch_remote_meta(self, meta_url: str) -> dict:
        """Fetches and parses a NVD `.meta` file (same key:value format as the
        per-year CVE feeds: lastModifiedDate/size/zipSize/gzSize/sha256)."""
        response = requests.get(meta_url, timeout=self.TIMEOUT)
        return self._parse_nvd_meta_data(response.text)

    def _download_feed_archive(self, url: str, file_name: str) -> "str | None":
        """Downloads (API mode) or locates (LOCAL mode) a NVD bulk `.tar.gz`
        feed archive under `temporary_directory`.

        API mode streams the response to disk (these archives can be hundreds
        of MB) rather than buffering in memory like the smaller per-year CVE
        downloads. LOCAL mode expects the file to already be present (not
        removed afterwards, consistent with how per-year `.json.gz` files are
        handled in LOCAL mode).
        """
        archive_path = os.path.join(self.temporary_directory, file_name)
        if self.fetch_mode == 'LOCAL':
            if not os.path.exists(archive_path):
                self.logger.fail(f"Local archive {file_name}", "NOT FOUND in temp-dir")
                return None
            return archive_path

        self.logger.trace(f"Downloading {url}")
        with requests.get(url, timeout=self.FEED_DOWNLOAD_TIMEOUT, stream=True) as response:
            if response.status_code != 200:
                self.logger.fail(f"Download {file_name}", f"HTTP {response.status_code}")
                return None
            with open(archive_path, "wb") as archive_file:
                for block in response.iter_content(chunk_size=1024 * 1024):
                    archive_file.write(block)
        self.logger.success(f"Download {file_name}", "DONE")
        return archive_path

    def _iter_archive_json_chunks(self, archive_path: str):
        """Yields the parsed JSON payload of each chunk file inside a NVD bulk
        `.tar.gz` feed archive (each chunk is itself a complete, page-shaped
        JSON object, e.g. `{"products": [...]}` or `{"matchStrings": [...]}`)."""
        with tarfile.open(archive_path, mode="r:gz") as tar:
            members = [member for member in tar.getmembers() if member.isfile()]
            for index, member in enumerate(members, start=1):
                fileobj = tar.extractfile(member)
                if fileobj is None:
                    continue
                self.logger.trace(f"Parsing chunk {index}/{len(members)}: {member.name}")
                yield json.load(fileobj)

    def _load_cpe_dictionary(self) -> None:
        """Syncs the full local CPE dictionary (`cpe_dictionary`) from the NVD
        CPE 2.0 bulk feed (`nvdcpe-2.0.tar.gz`, ~82MB compressed / ~1.8M
        entries), consistent with how per-year CVE feeds are downloaded and
        freshness-checked (same `.meta` format, reuses `nvd_meta` under the
        pseudo-year key `"CPE"`, same as the `"EPSS"` freshness row).
        """
        self.logger.trace("CPE dictionary sync: START")
        if self.fetch_mode == 'API':
            meta_data = self._fetch_remote_meta(self.CPE_DICTIONARY_META_URL)
        else:
            meta_data = {'lastModifiedDate': self._get_meta_date()}
        last_modified_date = meta_data.get('lastModifiedDate')
        if self._is_feed_up_to_date(str(last_modified_date), "CPE"):
            self.logger.trace("CPE dictionary up-to-date")
            return

        archive_path = self._download_feed_archive(self.CPE_DICTIONARY_FEED_URL, "nvdcpe-2.0.tar.gz")
        if archive_path is None:
            return

        total_synced = 0
        for payload in self._iter_archive_json_chunks(archive_path):
            products = payload.get("products", [])
            self._save_cpe_dictionary_page(products)
            self.conn.commit()
            total_synced += len(products)
        self._save_nvd_meta_data(meta_data, "CPE")
        self.conn.commit()
        if self.fetch_mode == 'API':
            os.remove(archive_path)
        self.logger.success("CPE dictionary sync", f"DONE ({total_synced} entries)")

    def _save_cpe_dictionary_page(self, products: list) -> None:
        """Parses one chunk's worth of NVD CPE `products` entries into `cpe_dictionary` rows."""
        rows = []
        for product in products:
            cpe = product.get("cpe", {})
            cpe_name = cpe.get("cpeName")
            cpe_name_id = cpe.get("cpeNameId")
            if not cpe_name or not cpe_name_id:
                continue
            parts = cpe_name.split(":")
            part = parts[2] if len(parts) > 2 else None
            vendor = parts[3] if len(parts) > 3 else None
            product_name = parts[4] if len(parts) > 4 else None
            version = parts[5] if len(parts) > 5 else None
            title = next(
                (t.get("title") for t in cpe.get("titles", []) if t.get("lang") == "en"),
                None,
            )
            rows.append((
                cpe_name_id,
                cpe_name,
                part,
                vendor,
                product_name,
                version,
                title,
                1 if cpe.get("deprecated") else 0,
                cpe.get("lastModified"),
                cpe.get("created"),
            ))
        if rows:
            self.cursor.executemany("""
                INSERT OR REPLACE INTO cpe_dictionary (
                    cpe_name_id, cpe_name, part, vendor, product, version,
                    title, deprecated, last_modified, created
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)

    def _load_cpe_match_resolutions(self) -> None:
        """Syncs the full CPE Match Criteria resolution feed
        (`cpe_match_resolutions`) from the NVD CPE-Match 2.0 bulk feed
        (`nvdcpematch-2.0.tar.gz`, ~795MB compressed / ~3.5GB uncompressed).

        This maps each `matchCriteriaId` (already stored per-CVE in
        `cpe_matches`) to the concrete CPE names NVD has resolved it to,
        letting `search_cves_by_cpe` match exactly instead of approximating
        version ranges itself.
        """
        self.logger.trace("CPE match resolution sync: START")
        if self.fetch_mode == 'API':
            meta_data = self._fetch_remote_meta(self.CPE_MATCH_META_URL)
        else:
            meta_data = {'lastModifiedDate': self._get_meta_date()}
        last_modified_date = meta_data.get('lastModifiedDate')
        if self._is_feed_up_to_date(str(last_modified_date), "CPE_MATCH"):
            self.logger.trace("CPE match resolution up-to-date")
            return

        archive_path = self._download_feed_archive(self.CPE_MATCH_FEED_URL, "nvdcpematch-2.0.tar.gz")
        if archive_path is None:
            return

        total_synced = 0
        for payload in self._iter_archive_json_chunks(archive_path):
            match_strings = payload.get("matchStrings", [])
            self._save_cpe_match_resolutions(match_strings)
            self.conn.commit()
            total_synced += len(match_strings)
        self._save_nvd_meta_data(meta_data, "CPE_MATCH")
        self.conn.commit()
        if self.fetch_mode == 'API':
            os.remove(archive_path)
        self.logger.success("CPE match resolution sync", f"DONE ({total_synced} entries)")

    def _save_cpe_match_resolutions(self, match_strings: list) -> None:
        """Parses one chunk's worth of NVD CPE-Match `matchStrings` entries
        into `cpe_match_resolutions` rows (one row per resolved concrete CPE).

        Deletes any previously stored rows for the affected matchCriteriaIds
        first, so re-parsing (e.g. LOCAL fetch mode always reprocessing) does
        not accumulate duplicates.
        """
        rows = []
        match_criteria_ids = set()
        for entry in match_strings:
            match_string = entry.get("matchString", {})
            match_criteria_id = match_string.get("matchCriteriaId")
            if not match_criteria_id:
                continue
            match_criteria_ids.add(match_criteria_id)
            for match in match_string.get("matches", []):
                cpe_name = match.get("cpeName")
                if cpe_name:
                    rows.append((match_criteria_id, cpe_name, match.get("cpeNameId")))

        for batch in _chunked(match_criteria_ids, SQLITE_MAX_VARIABLES):
            placeholders = ",".join("?" for _ in batch)
            self.cursor.execute(
                f"DELETE FROM cpe_match_resolutions WHERE match_criteria_id IN ({placeholders})",
                batch,
            )
        if rows:
            self.cursor.executemany("""
                INSERT INTO cpe_match_resolutions (match_criteria_id, cpe_name, cpe_name_id)
                VALUES (?, ?, ?)
            """, rows)

    def close(self):
        """Closes the database connection if it is open."""
        self.conn.close()
