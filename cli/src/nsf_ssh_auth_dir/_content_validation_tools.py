from collections import Counter
from typing import Iterable, Iterator, TypeVar

_T = TypeVar("_T")


def iter_duplicate_items(
        in_sequence: Iterable[_T]) -> Iterator[_T]:
    yield from (
        item
        for item, count in Counter(in_sequence).items()
        if count > 1)
