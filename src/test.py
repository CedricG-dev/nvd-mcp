import os
from tools.database_clients import DatabaseClient
from models.vulnerability import Vulnerability






def _create_data_fetcher() -> DatabaseClient:
    """Create the appropriate data fetcher based on the fetch mode."""
    database_path = os.getenv('CVE_DATABASE_PATH', 'data/vulnerability.db')
    print(database_path)
    return DatabaseClient(database_path)

cve_id = 'CVE-2025-53770'
data_fetcher = _create_data_fetcher()
vulnerability = Vulnerability(cve_id,"","")
data_fetcher.fetch_data(vulnerability)
print(vulnerability.render_mcp())