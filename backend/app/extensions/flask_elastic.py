from flask import Flask
from elasticsearch import Elasticsearch
import os


class FlaskElastic(Flask):
    
    def __init__(self, *args, **kwargs):
        config_class = kwargs['config_class']
        del kwargs['config_class']

        super().__init__(*args, **kwargs)

        self.config.from_object(config_class)
        
        self.elasticsearch = Elasticsearch([os.environ.get('ELASTICSEARCH_URL')]) \
            if os.environ.get('ELASTICSEARCH_URL') \
            else None