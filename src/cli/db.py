"""
Command-line interface for bmanage vloacl vulnerabbility database.

This module provides a CLI to:
- Load NVD datat from NVD feeds
- Load EPSS data drom FIRST feeds
"""

import argparse
import os

from tools.database_clients import DataBaseManager
from tools.logger import CLILogger
from models.config import  DatabaseManagementConfig
def main():
    """
    Entry point for the command-line interface for databse management utility.
    """
    load_db()


def load_db():
    """
    Entry point for the databse management CLI.
    """
    parser = _init_args_parser()
    config = _parse_config(parser.parse_args())
    logger = CLILogger("CLI PriorIT")
    logger.trace(str(config))
    database_path = os.getenv('CVE_DATABASE_PATH', 'data/vulnerability.db')
    db_manager = DataBaseManager(database_path,config.temp_directory,config.fetch_mode)
    db_manager.load_data(config.init_db)

def _init_args_parser():
    parser = argparse.ArgumentParser(description="Prioritize vulnerabilities based on CVSS, EPSS, and KEV scores.")
    parser.add_argument("--init",action='store_true',help="Create the database schema and fully (re)populate it: NVD CVE/EPSS data plus the CPE dictionary and CPE Match Criteria resolution bulk feeds (large one-time download, several hundred MB)")
    parser.add_argument("--temp-dir",type=str,required=False,default="",help="Temporary directory used to store downloade files")
    parser.add_argument("-f","--fetch-mode",choices=["LOCAL", "API"], default="API",metavar='LOCAL/API',help="Define sources of vulnerability data (Local folder (aka tmeporary file) with file preloaded files or APIs) ")
    return parser


def _parse_config(args) -> DatabaseManagementConfig:
    """Parse and validate CLI arguments into a configuration object."""
    return DatabaseManagementConfig(init_db=args.init,temp_directory=args.temp_dir,fetch_mode=args.fetch_mode)
