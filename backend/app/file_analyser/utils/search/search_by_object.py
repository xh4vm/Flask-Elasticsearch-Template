from typing import Optional, List
from itertools import chain
from ...models import Object
from .isearch import ISearch


class SearchByObject(ISearch):
    def __init__(self, s : Optional[str] = None, search_type : Optional[str] = None):
        self.s = s
        self.search_type = search_type

    def get(self) -> List[int]:
        _, _t = Object.search_ids(expression=self.s, search_type=self.search_type)  
        return _
