# VulnerabilityMCPServer

Test d'un serveur MCP local sur le protocol HTTP, avec un mode d'exposition
alternatif en API REST/JSON classique.

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

This installs every dependency needed to run the server (either mode) and
registers the two CLI commands used below, `vuln-db` and `vuln-server`, from
the single `pyproject.toml` manifest.

5) Build the local vulnerability database

The server reads from a local SQLite database (`data/vulnerability.db`,
git-ignored) that must be built before first use, with the `vuln-db` CLI:

```powershell
vuln-db --init
```

See [`docs/vuln-db.md`](docs/vuln-db.md) for the full CLI reference (flags,
environment variables, offline/LOCAL fetch mode, examples).

6) Launch the server

The vulnerability data can be exposed either over the **MCP protocol** or as
a plain **REST/JSON API**, chosen at startup with the `vuln-server` CLI:

```powershell
vuln-server --mode mcp     # MCP protocol, streamable-http, port 8001
vuln-server --mode rest    # REST/JSON API, port 8080
```

See [`docs/vuln-server.md`](docs/vuln-server.md) for the full CLI reference:
configuration (JSON config file per mode, overridable by CLI flags),
available MCP tools / REST routes, and how to test each mode (MCP Inspector /
Swagger UI).


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
