from typing import List, Tuple
from ..exceptions import DBExceptions
from flask import current_app


class Index:
    def __init__(self, index):
        self._elasticsearch_exist()
        self.index = index

    def _elasticsearch_exist(self):
        if not current_app.elasticsearch:
            raise DBExceptions('Elasticsearch not found')

    def add(self, model : object) -> None:
        payload = {field : getattr(model, field) for field in getattr(model, model.__searchable__)}
        current_app.elasticsearch.index(index=self.index, doc_type=self.index, id=model.id, body=payload)

    def remove(self, model : object) -> None:
        current_app.elasticsearch.delete(index=self.index, doc_type=self.index, id=model.id)

    def query(self, query : str, fields : List[str]) -> Tuple[list, int]:
        search = current_app.elasticsearch.search(index=self.index, doc_type=self.index, 
            body={'query': {'multi_match': {'query': query, 'fields': fields}}})

        return [int(hit['_id']) for hit in search['hits']['hits']], search['hits']['total']