from typing import List, Optional, Tuple, Union
from flask_sqlalchemy import BaseQuery
from .. import db
from .index import Index

from flask import current_app


class ElasticsearchMixin(object):

    @classmethod
    def add_if_not_exists(cls):
        return Index(cls.__tablename__).add_if_not_exists(cls)

    @classmethod
    def raw_search(cls, body : dict) -> Tuple[BaseQuery, int]:
        Index(cls.__tablename__).add_if_not_exists(cls)
        ids, total = Index(cls.__tablename__).raw_query(body=body)

        return cls.query.filter(cls.id.in_(ids)).all(), total['value']

    @classmethod
    def raw_search_ids(cls, body : dict) -> Tuple[BaseQuery, int]:
        Index(cls.__tablename__).add_if_not_exists(cls)
        return Index(cls.__tablename__).raw_query(body=body)

    @classmethod
    def raw_search_one(cls, body : dict) -> Optional[BaseQuery]:
        Index(cls.__tablename__).add_if_not_exists(cls)
        id = Index(cls.__tablename__).raw_query_one(body)

        return cls.query.filter(cls.id == id).first()

    @classmethod
    def raw_search_one_id(cls, body : dict) -> Optional[BaseQuery]:
        Index(cls.__tablename__).add_if_not_exists(cls)
        return Index(cls.__tablename__).raw_query_one(body)

    @classmethod
    def search_one(cls, expression : str) -> Optional[BaseQuery]:
        Index(cls.__tablename__).add_if_not_exists(cls)
        id = Index(cls.__tablename__).query_one(expression)

        return cls.query.filter(cls.id == id).first()

    @classmethod
    def search_one_id(cls, expression : str) -> Optional[BaseQuery]:
        Index(cls.__tablename__).add_if_not_exists(cls)
        return Index(cls.__tablename__).query_one(expression)

    @classmethod
    def search(cls, expression : str, fields : List[str] = ['*'], search_type : str = "best_fields") -> Tuple[BaseQuery, int]:
        Index(cls.__tablename__).add_if_not_exists(cls)
        ids, total = Index(cls.__tablename__).query(query=expression, fields=fields, search_type=search_type)

        # when = [(ids[i], i) for i in range(len(ids))]

        # r = cls.query.filter(cls.id.in_(ids)).order_by(db.case(when, value=cls.id)).all(), total['value']
        return cls.query.filter(cls.id.in_(ids)).all(), total['value']
   
    @classmethod
    def search_ids(cls, expression : str, fields : List[str] = ['*'], search_type : str = "best_fields") -> Tuple[BaseQuery, int]:
        Index(cls.__tablename__).add_if_not_exists(cls)
        return Index(cls.__tablename__).query(query=expression, fields=fields, search_type=search_type)

    @classmethod
    def before_commit(cls, session : dict) -> None:
        session._changes = {
            'add': list(session.new),
            'update': list(session.dirty),
            'delete': list(session.deleted)
        }

    @classmethod
    def after_commit(cls, session : dict) -> None:
        for key, changes in session._changes.items():
            for obj in changes:
                if not isinstance(obj, ElasticsearchMixin):
                    return
            
                if key == 'delete':
                    Index(obj.__tablename__).remove(obj)
                else:
                    Index(obj.__tablename__).add(obj)        

        session._changes = None

    @classmethod
    def reindex(cls) -> None:
        (Index(cls.__tablename__).add(cls))

db.event.listen(db.session, 'before_commit', ElasticsearchMixin.before_commit)
db.event.listen(db.session, 'after_commit', ElasticsearchMixin.after_commit)