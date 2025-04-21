# azure_defender_tool/logger_config.py
"""Configures the application-wide logger."""

import logging
import sys

# Store the handler globally to prevent adding it multiple times
_console_handler = None
_formatter = None

def setup_logger(name=__name__, level=logging.INFO):
    """Sets up and returns a configured logger instance."""
    global _console_handler, _formatter
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Only add the handler if the logger doesn't have one already
    if not logger.handlers:
        if _console_handler is None:
            _console_handler = logging.StreamHandler(sys.stdout)
            _formatter = logging.Formatter(
                '%(asctime)s [%(name)s] [%(levelname)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            _console_handler.setFormatter(_formatter)

        logger.addHandler(_console_handler)
        logger.propagate = True 
    return logger