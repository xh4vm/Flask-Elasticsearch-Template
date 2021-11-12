import json
from sqlalchemy.orm import relationship
from sqlalchemy.sql.sqltypes import String, Integer, BigInteger, SmallInteger
from sqlalchemy.sql.schema import CheckConstraint, Column, UniqueConstraint, ForeignKey
from ...db import Model, db
from ...db.elasticsearch.mixin import ElasticsearchMixin
import re


class AVInfo(Model, ElasticsearchMixin):
    __searchable__ = 'elastic_body'

    HARMLESS = 106101
    TYPE_UNSUPPORTED = 106102
    SUSPICIOUS = 106103
    CONFIRMED_TIMEOUT = 106104
    TIMEOUT = 106105
    FAILURE = 106106
    MALICIOUS = 106107
    UNDETECTED = 106108

    type_description = Column(String(128), nullable=False) 
    packer = Column(String(128), nullable=True)
    autostart_locations = Column(String(12288), nullable=True)
    popular_threat_name = Column(String(12288), nullable=True)
    popular_threat_category = Column(String(12288), nullable=True)
    status = Column(Integer, nullable=False)

    elastic_body = ['type_description', 'packer', 'autostart_locations', 'popular_threat_name', 'popular_threat_category', 'status']

    def __init__(self, type_description : str, status : int, packer : str = None, autostart_locations : object = None, creation_date : str = None, names : object = None, popular_threat_name : object = None, popular_threat_category : object = None):
        self.type_description = type_description
        self.packer = packer
        self.autostart_locations = json.dumps(autostart_locations)
        self.popular_threat_name = json.dumps(popular_threat_name)
        self.popular_threat_category = json.dumps(popular_threat_category)
        self.status = status

    def insert_if_not_exists_and_select(self):
        av_info = AVInfo.query.filter_by(type_description=self.type_description, packer=self.packer, 
            autostart_locations=self.autostart_locations, popular_threat_name=self.popular_threat_name, 
            popular_threat_category=self.popular_threat_category, status=self.status).first()

        if av_info is None:
            self.session.add(self)
            self.session.commit()

        return av_info or self


class VerdictAssociate(Model):

    hash_id = Column(BigInteger, ForeignKey('object_hashes.id'))
    av_verdict_id = Column(BigInteger, ForeignKey('av_verdicts.id'))


class  AVVerdict(Model, ElasticsearchMixin):
    __searchable__ = 'elastic_body'
    
    category = Column(String(128), nullable=False)
    engine_name = Column(String(128), nullable=False)
    engine_version = Column(String(128), nullable=True)
    result = Column(String(128), nullable=True)
    method = Column(String(4096), nullable=True)
    engine_update = Column(String(4096), nullable=True)

    elastic_body=['category', 'engine_name', 'engine_version', 'result', 'method', 'engine_update']

    def __init__(self, category : str, engine_name : str, engine_version : str = None, result : str = None, method : str = None, engine_update : str = None) -> None:
        self.category = category
        self.engine_name = engine_name
        self.engine_version = engine_version
        self.result = result
        self.method = method
        self.engine_update = engine_update
        
    def insert_if_not_exists_and_select(self):
        av_verdict = AVVerdict.query.filter_by(category=self.category, engine_name=self.engine_name, 
            engine_version=self.engine_version, result=self.result,
            method=self.method, engine_update=self.engine_update).first()

        if av_verdict is None:
            self.session.add(self)
            self.session.commit()

        return av_verdict or self