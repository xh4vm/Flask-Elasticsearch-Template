from abc import ABCMeta, abstractmethod
from typing import Union


class IHashHandler:
    __metaclass__ = ABCMeta

    @abstractmethod
    def get(self) -> Union[str, Exception]:
        '''Получение чистого параметра'''