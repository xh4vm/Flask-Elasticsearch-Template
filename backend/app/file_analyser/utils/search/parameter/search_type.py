from typing import Optional, List, Dict
from . import Parameter
from app.utils.redis_client import RedisClient


class SearchType(Parameter):
    __default__ = "best_fields"
    
    def __init__(self, validated_request : Optional[Dict[str,str]] = None):
        self.search_type = validated_request.get(self.__parameter__) or RedisClient.get_value(self.__parameter__)

    def cache_and_get(self):
        RedisClient.set_value(self.__parameter__, self.search_type)
        return self.search_type

    def get(self):
        return RedisClient.get_value(self.__parameter__) or self.__default__


