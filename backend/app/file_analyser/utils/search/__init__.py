from typing import Optional, Dict, List
from .search_by_object import SearchByObject
from .search_by_hash import SearchByHash
from .search_by_av_info import SearchByAVInfo
from .search_by_av_verdict import SearchByAVVerdict


class Search:
    def __init__(self, s : Optional[str] = None, search_type : Optional[str] = None, search_obj : Optional[Dict[str, str]] = None):
        self.s = s
        self.search_type = search_type
        self.search_obj = search_obj

    def get(self) -> Optional[List[int]]:
        if self.s is None:
            return None

        ids = []

        if 'objects' in self.search_obj:
            ids.extend(SearchByObject(s=self.s, search_type=self.search_type).get())

        if 'hashes' in self.search_obj:
            ids.extend(SearchByHash(s=self.s, search_type=self.search_type).get())

        if 'av_info' in self.search_obj:
            ids.extend(SearchByAVInfo(s=self.s, search_type=self.search_type).get())

        if 'av_verdict' in self.search_obj:
            ids.extend(SearchByAVVerdict(s=self.s, search_type=self.search_type).get())

        return ids