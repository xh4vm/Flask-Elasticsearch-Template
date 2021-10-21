from typing import Optional, List
from itertools import chain
from ...discovery.models import AVInfo
from .isearch import ISearch


class SearchByAVInfo(ISearch):
    def __init__(self, s : Optional[str] = None, search_type : Optional[str] = None):
        self.s = s
        self.search_type = search_type

    def get(self) -> List[int]:
        _av_info_search, ti = AVInfo.search(expression=self.s, search_type=self.search_type)
        return [o.id for o in 
            chain(*[h.object for h in 
            chain(*[a.hashes for a in _av_info_search])])]
