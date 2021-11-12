from typing import Optional, List
from itertools import chain
from ...models import Hash
from .isearch import ISearch


class SearchByHash(ISearch):
    def __init__(self, s : Optional[str] = None, search_type : Optional[str] = None):
        self.s = s
        self.search_type = search_type

    def get(self) -> List[int]:
        _hash_result_search, th = Hash.search(expression=self.s, search_type=self.search_type)
        return list(chain(*[[o.id for o in h.object] for h in _hash_result_search]))
