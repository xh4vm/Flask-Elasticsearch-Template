from json import loads, dumps
from base64 import b64decode, b64encode
from typing import Optional, List, Dict
from . import Parameter
from app.utils.redis_client import RedisClient


class SearchObj(Parameter):
    __default__ = ["objects", "hashes"]
    
    def __init__(self, validated_request : Optional[Dict[str,str]] = None):
        _search_obj = validated_request.get(self.__parameter__) 
        self.search_obj = b64decode(_search_obj).decode() if _search_obj is not None else RedisClient.get_value(self.__parameter__)

    def cache_and_get(self):
        RedisClient.set_value(self.__parameter__, self.search_obj)
        return loads(self.search_obj) if self.search_obj is not None else []

    def get(self):
        return RedisClient.get_value(self.__parameter__) or self.__default__

    def b64_encode(self):
        _ = self.search_obj if self.search_obj is not None else dumps([])
        return b64encode(_.encode())