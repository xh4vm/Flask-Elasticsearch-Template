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

    def add_if_not_exists(self, model : object):
        indices = current_app.elasticsearch.indices.get('*')

        if model.__tablename__ in indices:
            return False

        current_app.elasticsearch.indices.create(index=self.index, body={})
        
        return True

    def add(self, model : object) -> dict:
        payload = {field : getattr(model, field) for field in getattr(model, model.__searchable__)}
        return current_app.elasticsearch.index(index=self.index, id=model.id, body=payload, refresh='true')

    def remove(self, model : object) -> None:
        current_app.elasticsearch.delete(index=self.index, id=model.id)

    def raw_query(self, body : dict) -> Tuple[list, int]:
        search = current_app.elasticsearch.search(index=self.index, body=body)
        return [int(hit['_id']) for hit in search['hits']['hits']], search['hits']['total']

    def raw_query_one(self, body : dict) -> list:
        search = current_app.elasticsearch.search(index=self.index, body=body)
        return int(search['hits']['hits'][0]['_id']) if len(search['hits']['hits']) > 0 else None

    def query_one(self, args : dict) -> list:
        search = current_app.elasticsearch.search(index=self.index,  
            body={'query': {'match': args}, 'size': 1})

        return int(search['hits']['hits'][0]['_id']) if len(search['hits']['hits']) > 0 else None

    def query(self, query : str, fields : List[str], search_type : str) -> Tuple[list, int]:
        if search_type == "best_fields":
            body = {'query': {'multi_match': {'query': query, 'fields': fields}}}
        elif search_type == "fuzziness":
            body = {'query': {'multi_match': {'query': query, 'fields': fields, "fuzziness": "auto"}}}
        elif search_type == "bool_prefix":
            body = {'query': {'multi_match': {'query': query, 'fields': fields, "type": search_type}}}
        
        search = current_app.elasticsearch.search(index=self.index, body=body)

        return [int(hit['_id']) for hit in search['hits']['hits']], search['hits']['total']
