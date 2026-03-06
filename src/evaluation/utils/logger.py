"""Simple logger for evaluation toolkit."""
import logging
import sys
from typing import Optional


def get_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """
    Get configured logger for evaluation toolkit.

    Args:
        name: Logger name (usually __name__)
        level: Log level (DEBUG, INFO, WARNING, ERROR). Defaults to INFO.

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    # Only add handler if logger doesn't have one
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    # Set level
    log_level = level or 'INFO'
    logger.setLevel(getattr(logging, log_level.upper()))

    return logger
