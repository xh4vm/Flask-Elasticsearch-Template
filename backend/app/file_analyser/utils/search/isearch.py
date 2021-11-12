from abc import ABCMeta, abstractmethod
from typing import List, Optional


class ISearch:
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self, s : Optional[str] = None, search_type : Optional[str] = None):
        ''' Конструктор '''

    @abstractmethod
    def get(self) -> List[int]:
        '''Получение id объектов'''
    
