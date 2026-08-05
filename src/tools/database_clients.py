"""
Database clients for fetching vulnerability data from database with pre-loaded data .

This module provides classes to interact with the database, fetching details such as CVSS scores,
EPSS scores, and KEV status for vulnerabilities.
"""

import sqlite3
from models.vulnerability import Vulnerability
from tools.logger import CLILogger

class DatabaseClient():


    def __init__(self, db_path: str):
        self.logger = CLILogger("DatabaseClient")
        self.conn = sqlite3.connect(db_path)
        self.cur = self.conn.cursor()


    def fetch_data(self, vulnerability: Vulnerability):
        """
        Fetches data from the databse and populates the vulnerability object.
        Args:
            vulnerability: Vulnerability object to populate with API data.
        """
        self.logger.trace(f"Fetch {vulnerability.cve_id}: START")
        self.cur.execute("""
            SELECT cve_id, base_cvss_score, vector, version, severity, description, has_kev,epss_score,epss_percentile,published_date,exploit_date,references_count,weaknesses_count
            FROM cves
            WHERE cve_id = ?
        """, (vulnerability.cve_id,))
        result = self.cur.fetchone()
        if result:
            vulnerability.base_cvss_score = result[1]
            vulnerability.cvss_score = result[1]
            vulnerability.vector =result[2]
            vulnerability.version =result[3]
            vulnerability.severity = result[4]
            vulnerability.description = result[5]
            vulnerability.has_kev=bool(result[6])
            vulnerability.epss_score = result[7] * 100 if result[7] is not None else 0
            vulnerability.epss_percentile = result[8] * 100 if result[8] is not None else 0
            vulnerability.published_date = result[9]
            vulnerability.exploit_date = result[10]
            vulnerability.references_count = result[11]
            vulnerability.weaknesses_count = result[12]
            self.logger.success(f"Fetch {vulnerability.cve_id}","DONE")
        else:
            self.logger.fail(f"Fetch {vulnerability.cve_id}","NOT FOUND")