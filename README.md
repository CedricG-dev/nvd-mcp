# VulnerabilityMCPServer

Test d'un serveur MCP local sur le protocol HTTP

## Prerequisites 

A python version 3.9+ should be installed

NPM should be installed (using NodeJS installation)

## Set up environment

1) Clone the Github repo

2) Create a virtual environment linked to the project

```powershell
python -m venv <PATH_TO_YOU_VENV_FOLDER>\VulnerabilityMCPServer
```

3) Start the virtual environment

```powershell
<PATH_TO_YOU_VENV_FOLDER>\Scripts\Activate.ps1
```

Use other script based on your environment type (activate / activate.bat)

4) Install python packages

```powershell
pip install -e .
```

This installs every dependency needed to both run the MCP server and use the
`vuln-db` CLI (also registered by this command), from the single
`pyproject.toml` manifest.

5) Build the local vulnerability database

The server reads from a local SQLite database (`data/vulnerability.db`,
git-ignored) that must be built before first use, with the `vuln-db` CLI
(always run from the repo root):

```powershell
vuln-db --init
```

`--init` creates the database tables and does a full live sync against NVD/EPSS
(CVE + EPSS data), plus the CPE dictionary and CPE-match feeds used by the
`resolve_cpe`/`search_cves_by_cpe` tools. It's required on first run, is safe
to rerun, and can take a while (the CPE-match feed alone is ~795MB
compressed).

6) Launch the MCP server

```powershell
fastmcp run
```


The terminal should render: 

![SERVER START](pictures/launch-server.png)


The default configuation is set by file `fastmcp.json`

```json
{
  "$schema": "https://gofastmcp.com/public/schemas/fastmcp.json/v1.json",
  "source": {
    "path": "src/vulnerability-mcp-server.py",
    "entrypoint": "mcp"
  },
  "deployment": {
    "transport": "streamable-http",
    "port":8000,
    "path": "/nvd-mcp",
    "log_level": "INFO"
  }
}
```

> [!TIP]
> If you need to change it and update some configuration like port or deployment path, adapt following documentation to your updates.


## Test MCP server

Open another terminal and launch the command 

```powershell
npx @modelcontextprotocol/inspector
```

> if a prompt ask you if you want to install the package accept


Now a browser is opened and display MCP inspector

![MCP INSPECTOR](pictures/inspector.png)

Click on `Add Servers` and select `+ Add manually`

Set `NVD-MCP` as Server ID

Select `streamable-http` as Transport

Set URL with **http://localhost:8000/nvd-mcp** and click on Add

A new server appears: 

![MCP INSPECTOR](pictures/new-server.png)

Toggle on the Connection button at the top-right of the server card

Some info should appear on a right side bar.


Click on `Tools` and select `get_cve_by_id`.

![TOOL PICTURES](pictures/tool.png)


Fill `cve_id` with for example _CVE-2025-53770_

![RESULT](pictures/result.png)


## Available tools

All tools are 100% local at query time (they read from `data/vulnerability.db`,
no outbound network calls, no API key required):

| Tool | Description |
| --- | --- |
| `get_cve_by_id(cve_id)` | Full detail for one CVE, formatted as text. |
| `batch_search_cves(cve_ids)` | Same as `get_cve_by_id` but for a batch of CVE ids, returning raw fields per id (plus a `found` flag for ids missing locally). |
| `search_cves_by_keyword(keyword, limit=50)` | Substring search over CVE descriptions, ordered by CVSS score (descending). |
| `get_epss_score(cve_ids)` | EPSS score/percentile (raw 0-1 fractions) for a list of CVE ids. |
| `check_kev_status(cve_ids)` | Whether each CVE id is listed in the CISA KEV catalog (boolean membership only). |
| `get_nvd_sync_status()` | Freshness of the local NVD-derived data, to help decide if a DB refresh is needed. |
| `search_cves_by_cpe(cpe, limit=50)` | CVEs affecting a given CPE 2.3 string (full or partial, e.g. `cpe:2.3:a:apache:log4j:2.14.1` or just `cpe:2.3:a:apache:log4j`). |
| `resolve_cpe(keyword, limit=50)` | Keyword search (vendor/product/title) against the CPE dictionary, e.g. to find the exact CPE name for a product before calling `search_cves_by_cpe`. Requires `vuln-db --init` to have been run. |

See `AGENTS.md` for the full details of each tool (return shapes, match
precision semantics, etc.).


## Run OpenCode

Now you can run OpenCode in a third terminal. 

```powershell
opencode
```

you get 

![OPENCODE](pictures/opencode.png)

use the command `/mcps` to list mcp servers

![OPENCODE MCP](pictures/mcps.png)

Now test the following prompt

```text

get info about vulnerability with id  CVE-2025-53770 and trace if you used a mcp server and a tool in your response

```

We get the following response with local LLM `qwen3.6:latest`

![RESPONSE QWEN](pictures/response-qwen.png)

We get the following response with remote `Claude Sonnet 5`

![RESPONS SONNET](pictures/response-claude.png)