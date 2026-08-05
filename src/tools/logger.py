"""
CLI Logger Module

This module provides a custom logger for command-line interfaces (CLI) with colored output.
It wraps Python's built-in `logging` module and adds methods for success, failure, and warning messages
with color highlighting using `colorama`.
"""

import logging
from colorama import Fore,Style, init

init(autoreset=True)

class CLILogger:
    """
    A custom CLI logger with colored output for trace, success, failure, and warning messages.

    Attributes:
        name (str): The name of the logger.
        logger (logging.Logger): The underlying Python logger instance.
    """

    def __init__(self,name:str, level: int = logging.INFO) -> None:
        """
        Initialize the CLI logger.

        Args:
            name: The name of the logger.
            level: The logging level (default: logging.INFO).
        """
        self.name = name
        self.logger = logging.getLogger(name)
        if not self.logger.handlers:
            self.logger.setLevel(level)
            handler = logging.StreamHandler()
            formatter = logging.Formatter('[%(asctime)s - %(name)s - %(levelname)s] %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.propagate=False

    def trace(self,message:str):
        """
        Log a trace message.

        Args:
            message (str): The message to log.
        """
        self.logger.info(message)
        for handler in self.logger.handlers:
            handler.flush()

    def success(self, message:str, status:str):
        """
        Log a success message with green-colored status.

        Args:
            message (str): The message to log.
            status (str): The status to highlight in green.
        """
        colored_status = f"{Fore.GREEN}{status}{Style.RESET_ALL}"
        self.logger.info("%s: %s", message, colored_status)
        for handler in self.logger.handlers:
            handler.flush()

    def fail(self, message:str, status:str):
        """
        Log a failure message with red-colored status.

        Args:
            message (str): The message to log.
            status (str): The status to highlight in red.
        """
        colored_status = f"{Fore.RED}{status}{Style.RESET_ALL}"
        self.logger.error("%s: %s", message, colored_status)
        for handler in self.logger.handlers:
            handler.flush()

    def warning(self, message:str):
        """
        Log a warning message with yellow-colored text.

        Args:
            message (str): The message to log.
        """
        colored_message = f"{Fore.YELLOW}{message}{Style.RESET_ALL}"
        self.logger.warning("%s", colored_message)
        for handler in self.logger.handlers:
            handler.flush()
