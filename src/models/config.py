"""
Module defining the configuration dataclass for vulnerability prioritization.


"""
from dataclasses import dataclass
from colorama import Fore,Style




@dataclass
class DatabaseManagementConfig:
    """Stores configuration parameters for databse management.

    This class centralizes all the settings needed to run the databse management process.

    Attributes:
        init_db (bool): Flag to indicate if the database should be created and
            fully populated (schema + NVD/EPSS data + CPE dictionary + CPE
            Match Criteria resolutions).
        temp_directory (str): trmporary folder to store uploaded files.
        fetch_mode (str): load mode
    """

    init_db: bool
    temp_directory: str
    fetch_mode: str



    def __str__(self):
        return f"""=== Database Management Arguments ===
        Init DB": {Fore.LIGHTBLUE_EX}{self.init_db}{Style.RESET_ALL}
        Temporary directory: {Fore.LIGHTBLUE_EX}{self.temp_directory}{Style.RESET_ALL}
        Fetch mode: {Fore.LIGHTBLUE_EX}{self.fetch_mode}{Style.RESET_ALL}
        """


@dataclass
class ServerRuntimeConfig:
    """Stores the runtime configuration used to start the vulnerability server.

    Centralizes the settings needed to decide, at startup, whether the
    vulnerability data is exposed over the MCP protocol (`streamable-http`
    transport) or as a plain REST/JSON API, and on which host/port/path.
    Resolved by `server.py` from (in order of precedence) CLI flags, the
    mode's JSON config file (`fastmcp.json` for mcp, `rest.json` for rest),
    then built-in defaults.

    Attributes:
        mode (str): Exposition mode, either "mcp" or "rest".
        host (str): Host/interface to bind the server to.
        port (int): TCP port to bind the server to.
        path (str): URL path the server is mounted on (MCP mode only; REST
            routes are mounted at the root of the app).
        log_level (str): Log level passed down to the underlying server.
    """

    mode: str
    host: str
    port: int
    path: str
    log_level: str

    def __str__(self):
        return f"""=== Server Runtime Arguments ===
        Mode: {Fore.LIGHTBLUE_EX}{self.mode}{Style.RESET_ALL}
        Host: {Fore.LIGHTBLUE_EX}{self.host}{Style.RESET_ALL}
        Port: {Fore.LIGHTBLUE_EX}{self.port}{Style.RESET_ALL}
        Path: {Fore.LIGHTBLUE_EX}{self.path}{Style.RESET_ALL}
        Log level: {Fore.LIGHTBLUE_EX}{self.log_level}{Style.RESET_ALL}
        """
