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
