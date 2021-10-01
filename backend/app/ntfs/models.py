import json
from sqlalchemy.orm import relationship
from sqlalchemy.sql.sqltypes import String, Integer, BigInteger
from sqlalchemy.sql.schema import Column, UniqueConstraint, ForeignKey
from ..db import Model, db
from ..db.elasticsearch.mixin import ElasticsearchMixin


class Fingerprint(Model):
    __searchable__ = 'elastic_body'
    __table_args__ = (UniqueConstraint('serial_number', 'friendly_name', 'computer_name', name='uq_fingerprint'),)

    serial_number = Column(String(1024), nullable=True)
    friendly_name = Column(String(1024), nullable=True)
    net_settings = Column(String(1024), nullable=True)
    computer_name = Column(String(1024), nullable=True)

    elastic_body=['serial_number', 'friendly_name', 'net_settings', 'computer_name']

    def __init__(self, serial_number : str, friendly_name : str, net_settings : str, computer_name : str):
        self.serial_number = serial_number
        self.friendly_name = friendly_name
        self.net_settings = net_settings
        self.computer_name = computer_name

    def add(self):
        if Fingerprint.query.filter_by(friendly_name=self.friendly_name, serial_number=self.serial_number, computer_name=self.computer_name).first() is not None:
            self.session.add(self)
            self.session.commit()

class Object(Model, ElasticsearchMixin):
    __searchable__ = 'elastic_body'
    __table_args__ = (UniqueConstraint('path', 'md5_hash', name='uq_file'),)

    fingerprint_id = Column(BigInteger, ForeignKey('fingerprints.id'))
    path = Column(String(4096), nullable=False)
    md5_hash = Column(String(32), nullable=True)
    creation_time = Column(String(16), nullable=False)
    last_write_time = Column(String(16), nullable=False)

    elastic_body=['fingerprint_id', 'serial_number', 'path', 'md5_hash', 'creation_time', 'last_write_time']

    def __init__(self, fingerprint_id : int, path : str, md5_hash : str, creation_time : str, last_write_time : str, serial_number : str = None) -> None:
        self.fingerprint_id = fingerprint_id
        self.path = path
        self.md5_hash = md5_hash
        self.creation_time = creation_time
        self.last_write_time = last_write_time
        self.serial_number = serial_number

class ObjectAssociate(Model):

    object_id = Column(BigInteger, ForeignKey('objects.id'))
    av_info_id = Column(BigInteger, ForeignKey('av_infos.id'))

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

    type_description = Column(String(1024), nullable=False) 
    packer = Column(String(4096), nullable=True)
    autostart_locations = Column(String(1228800), nullable=True)
    creation_date = Column(String(16), nullable=True)
    names = Column(String(1228800), nullable=True)
    popular_threat_name = Column(String(1228800), nullable=True)
    popular_threat_category = Column(String(1228800), nullable=True)
    status = Column(Integer, nullable=False)

    elastic_body = ['type_description', 'packer', 'autostart_locations', 'creation_date', 'names', 'popular_threat_name', 'popular_threat_category', 'status']

    def __init__(self, type_description : str, status : int, packer : str = None, autostart_locations : object = None, creation_date : str = None, names : object = None, popular_threat_name : object = None, popular_threat_category : object = None):
        self.type_description = type_description
        self.packer = packer
        self.autostart_locations = json.dumps(autostart_locations)
        self.creation_date = creation_date
        self.names = json.dumps(names)
        self.popular_threat_name = json.dumps(popular_threat_name)
        self.popular_threat_category = json.dumps(popular_threat_category)
        self.status = status

    def add(self):
        if AVInfo.query.filter_by(friendly_name=self.friendly_name, serial_number=self.serial_number, computer_name=self.computer_name).first() is not None:
            self.session.add(self)
            self.session.commit()

class  AVVerdict(Model, ElasticsearchMixin):
    __searchable__ = 'elastic_body'
    
    object_id = Column(BigInteger, ForeignKey('objects.id'))
    category = Column(String(4096), nullable=False)
    engine_name = Column(String(4096), nullable=False)
    engine_version = Column(String(4096), nullable=True)
    result = Column(String(128), nullable=True)
    method = Column(String(4096), nullable=True)
    engine_update = Column(String(4096), nullable=True)

    elastic_body=['object_id', 'category', 'engine_name', 'engine_version', 'result', 'method', 'engine_update']

    def __init__(self, object_id : int, category : str, engine_name : str, engine_version : str = None, result : str = None, method : str = None, engine_update : str = None) -> None:
        self.object_id = object_id
        self.category = category
        self.engine_name = engine_name
        self.engine_version = engine_version
        self.result = result
        self.method = method
        self.engine_update = engine_update
