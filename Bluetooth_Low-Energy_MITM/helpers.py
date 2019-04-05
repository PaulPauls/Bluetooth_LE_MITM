import logging
import logging.config

import yaml


def setup_logging():
    """
    Setup logging configuration
    """
    with open('../logs/logging.yaml', 'rt') as f:
        log_config = yaml.safe_load(f.read())
    logging.config.dictConfig(log_config)
