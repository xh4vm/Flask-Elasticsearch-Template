from typing import Optional
from app import redis_client


class RedisClient:

    @staticmethod
    def set_value(name : str, value : Optional[str]):
        if value is None:
            return 
        redis_client.set(name, value)

    @staticmethod
    def get_value(name : str):
        value = redis_client.get(name)
        return value.decode() if value is not None else None
