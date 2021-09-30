from sqlalchemy.orm import relationship
from sqlalchemy.sql.sqltypes import String, Integer, BigInteger
from sqlalchemy.sql.schema import Column, UniqueConstraint, ForeignKey
from ..db import Model, db
from ..db.elasticsearch.mixin import ElasticsearchMixin


class Object(Model, ElasticsearchMixin):
    __searchable__ = 'elastic_body'
    __table_args__ = (UniqueConstraint('path', 'md5_hash', name='uq_file'),)

    serial_number = Column(String(128), nullable=True)
    path = Column(String(128), nullable=False)
    md5_hash = Column(String(128), nullable=True)
    creation_time = Column(String(128), nullable=False)
    last_write_time = Column(String(128), nullable=False)

    elastic_body=['serial_number', 'path', 'md5_hash', 'creation_time', 'last_write_time']

    def __init__(self, path : str, md5_hash : str, creation_time : str, last_write_time : str, serial_number : str = None) -> None:
        self.path = path
        self.md5_hash = md5_hash
        self.creation_time = creation_time
        self.last_write_time = last_write_time
        self.serial_number = serial_number
    
class ObjectInfo(Model, ElasticsearchMixin):
    __searchable__ = 'elastic_body'

    HARMLESS = 106101
    TYPE_UNSUPPORTED = 106102
    SUSPICIOUS = 106103
    CONFIRMED_TIMEOUT = 106104
    TIMEOUT = 106105
    FAILURE = 106106
    MALICIOUS = 106107
    UNDETECTED = 106108

    object_id = Column(BigInteger, ForeignKey('objects.id'))
    type_description = Column(String(128), nullable=False) 
    packer = Column(String(128), nullable=True)
    autostart_locations = Column(String(12288), nullable=True)
    creation_date = Column(String(128), nullable=True)
    meaningful_name = Column(String(128), nullable=True)
    popular_threat_name = Column(String(12288), nullable=True)
    popular_threat_category = Column(String(12288), nullable=True)
    status = Column(Integer, nullable=False)

    elastic_body = ['object_id', 'type_description', 'packer', 'autostart_locations', 'creation_date', 'meaningful_name', 'popular_threat_name', 'popular_threat_category', 'status']

    def __init__(self, type_description : str, status : int, packer : str = None, autostart_locations : str = None, creation_date : str = None, meaningful_name : str = None, popular_threat_name : str = None, popular_threat_category : str = None):
        self.type_description = type_description
        self.packer = packer
        self.autostart_locations = autostart_locations
        self.creation_date = creation_date
        self.meaningful_name = meaningful_name
        self.popular_threat_name = popular_threat_name
        self.popular_threat_category = popular_threat_category
        self.status = status

class  AVVerdict(Model, ElasticsearchMixin):
    __searchable__ = 'elastic_body'
    
    object_id = Column(BigInteger, ForeignKey('objects.id'))
    category = Column(String(128), nullable=False)
    engine_name = Column(String(128), nullable=False)
    engine_version = Column(String(128), nullable=True)
    result = Column(String(128), nullable=True)
    method = Column(String(128), nullable=True)
    engine_update = Column(String(128), nullable=True)

    elastic_body=['object_id', 'category', 'engine_name', 'engine_version', 'result', 'method', 'engine_update']

    def __init__(self, object_id : int, category : str, engine_name : str, engine_version : str = None, result : str = None, method : str = None, engine_update : str = None,) -> None:
        self.object_id = object_id
        self.category = category
        self.engine_name = engine_name
        self.engine_version = engine_version
        self.result = result
        self.method = method
        self.engine_update = engine_update
