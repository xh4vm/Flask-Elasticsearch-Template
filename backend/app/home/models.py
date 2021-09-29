from sqlalchemy.orm import relationship
from sqlalchemy.sql.sqltypes import String, Integer
from sqlalchemy.sql.schema import Column
from ..db import Model, db
from ..db.elasticsearch.mixin import ElasticsearchMixin


class User(Model, ElasticsearchMixin):
    __searchable__ = 'elastic_body'

    nickname = Column(String(128), nullable=False, unique=True)
    first_name = Column(String(128), nullable=True)
    email = Column(String(128), nullable=False, unique=True)

    elastic_body=['nickname', 'first_name', 'email']

    def __init__(self, nickname : str, first_name : str, email : str) -> None:
        self.nickname = nickname
        self.first_name = first_name
        self.email = email
