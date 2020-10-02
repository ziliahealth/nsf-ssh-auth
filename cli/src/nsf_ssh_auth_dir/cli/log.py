import logging


def setup_verbose(
        verbose: int) -> None:
    verbosity_mapping = {
        0: logging.WARNING,
        1: logging.INFO,
        2: logging.DEBUG,
    }
    assert verbose >= 0
    logging.basicConfig(
        level=verbosity_mapping.get(verbose, logging.DEBUG))
