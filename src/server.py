"""
Unified launcher for the Vulnerability Data Source server.

Lets the operator choose, at startup, whether the vulnerability data is
exposed over the MCP protocol (`streamable-http` transport) or as a plain
REST/JSON API (FastAPI + uvicorn), via the `--mode` CLI flag.

Configuration (host/port/path/log_level) is unified between the two modes:
each mode reads its defaults from a JSON config file (same `deployment`
shape for both), which can in turn be overridden by CLI flags.

    CLI flag  >  JSON config file (per mode)  >  built-in default

- MCP mode reads `fastmcp.json` by default.
- REST mode reads `rest.json` by default.
- `--config <path>` overrides which JSON file is read.

Examples:
    vuln-server                                  # MCP mode (default), config from fastmcp.json
    vuln-server --mode mcp                        # same, explicit
    vuln-server --mode rest                       # REST mode, config from rest.json
    vuln-server --mode rest --port 9000           # REST mode, port overridden on the CLI
    vuln-server --mode rest --config custom.json  # REST mode, alternate config file
"""

import argparse
import importlib.util
import json
from pathlib import Path

from models.config import ServerRuntimeConfig
from tools.logger import CLILogger

DEFAULT_MCP_PORT = 8001
DEFAULT_REST_PORT = 8080
DEFAULT_MCP_PATH = "/nvd-mcp"
DEFAULT_REST_PATH = ""
DEFAULT_HOST = "127.0.0.1"
DEFAULT_LOG_LEVEL = "INFO"

# Default JSON config file read for each mode (looked up relative to the
# current working directory, same convention as `fastmcp run` used before:
# always run `vuln-server` from the repo root).
DEFAULT_CONFIG_FILES = {
    "mcp": "fastmcp.json",
    "rest": "rest.json",
}

# The MCP entrypoint module (`src/vulnerability-mcp-server.py`) uses a
# hyphenated filename, which is not a valid Python identifier, so it can't be
# `import`-ed normally. It's loaded by file path instead, resolved relative
# to this file so it works regardless of the current working directory or
# install method.
_MCP_MODULE_PATH = Path(__file__).resolve().parent / "vulnerability-mcp-server.py"


def main():
    """Entry point for the `vuln-server` CLI."""
    parser = _init_args_parser()
    args = parser.parse_args()
    config = _resolve_config(args)
    logger = CLILogger("Server Launcher")
    logger.trace(str(config))

    if config.mode == "mcp":
        _run_mcp(config)
    else:
        _run_rest(config)


def _init_args_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Launch the Vulnerability Data Source server, exposed either as MCP or as a REST API."
    )
    parser.add_argument(
        "-m", "--mode", choices=["mcp", "rest"], default="mcp",
        help="Exposition mode (default: mcp).",
    )
    parser.add_argument(
        "-c", "--config", type=str, default=None,
        help="Path to the JSON config file for the selected mode "
             f"(default: {DEFAULT_CONFIG_FILES['mcp']} for mcp, {DEFAULT_CONFIG_FILES['rest']} for rest).",
    )
    parser.add_argument("--host", type=str, default=None, help=f"Host/interface to bind to (default: {DEFAULT_HOST}).")
    parser.add_argument("--port", type=int, default=None, help="TCP port to bind to (default: from config file).")
    parser.add_argument(
        "--path", type=str, default=None,
        help="URL path/prefix to mount the server on "
             f"(default: {DEFAULT_MCP_PATH} for mcp, root for rest). "
             "In rest mode, all routes are mounted under this prefix, e.g. '/api' -> /api/health.",
    )
    parser.add_argument("--log-level", type=str, default=None, help=f"Log level (default: {DEFAULT_LOG_LEVEL}).")
    return parser


def _load_deployment_config(config_path: str) -> dict:
    """Loads the `deployment` section of a mode's JSON config file.

    Returns an empty dict if the file doesn't exist, so callers transparently
    fall back to built-in defaults.
    """
    path = Path(config_path)
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8") as config_file:
        data = json.load(config_file)
    return data.get("deployment", {})


def _resolve_config(args: argparse.Namespace) -> ServerRuntimeConfig:
    """Resolves the runtime config: CLI flag > JSON config file (per mode) > built-in default."""
    mode = args.mode
    config_path = args.config or DEFAULT_CONFIG_FILES[mode]
    deployment = _load_deployment_config(config_path)

    default_port = DEFAULT_MCP_PORT if mode == "mcp" else DEFAULT_REST_PORT
    default_path = DEFAULT_MCP_PATH if mode == "mcp" else DEFAULT_REST_PATH
    host = args.host or deployment.get("host", DEFAULT_HOST)
    port = args.port or deployment.get("port", default_port)
    path = args.path or deployment.get("path", default_path)
    log_level = args.log_level or deployment.get("log_level", DEFAULT_LOG_LEVEL)

    return ServerRuntimeConfig(mode=mode, host=host, port=int(port), path=path, log_level=log_level)


def _load_mcp_app():
    """Loads the `mcp` FastMCP instance from `vulnerability-mcp-server.py` by file path."""
    spec = importlib.util.spec_from_file_location("vulnerability_mcp_server", _MCP_MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.mcp


def _run_mcp(config: ServerRuntimeConfig) -> None:
    """Starts the vulnerability data source over the MCP protocol (streamable-http)."""
    mcp = _load_mcp_app()
    mcp.run(
        transport="streamable-http",
        host=config.host,
        port=config.port,
        path=config.path,
        log_level=config.log_level,
    )


def _run_rest(config: ServerRuntimeConfig) -> None:
    """Starts the vulnerability data source as a REST API (FastAPI + uvicorn),
    with all routes mounted under `config.path` (empty/root by default)."""
    import uvicorn

    from rest_api import build_app

    rest_app = build_app(config.path)
    uvicorn.run(rest_app, host=config.host, port=config.port, log_level=config.log_level.lower())


if __name__ == "__main__":
    main()
