from typing import List, Tuple
from flask_sqlalchemy import BaseQuery
from .. import db
from .index import Index


class ElasticsearchMixin(object):
    @classmethod
    def search(cls, expression : str, fields : List[str]) -> Tuple[BaseQuery, int]:
        ids, total = Index(cls.__tablename__).query(expression, fields)
        when = [(ids[i], i) for i in range(len(ids))]
        
        return cls.query.filter(cls.id.in_(ids)).order_by(db.case(when, value=cls.id)).all(), total['value']

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