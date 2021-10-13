import json
from sqlalchemy.orm import relationship
from sqlalchemy.sql.sqltypes import String, Integer, BigInteger, SmallInteger
from sqlalchemy.sql.schema import CheckConstraint, Column, UniqueConstraint, ForeignKey
from ..db import Model, db
from ..db.elasticsearch.mixin import ElasticsearchMixin


class Fingerprint(Model):
    __table_args__ = (UniqueConstraint('serial_number', 'friendly_name', 'computer_name', name='uq_fingerprint'),)

    serial_number = Column(String(1024), nullable=True)
    friendly_name = Column(String(1024), nullable=True)
    net_settings = Column(String(1024), nullable=True)
    computer_name = Column(String(1024), nullable=True)

    def __init__(self, serial_number : str, friendly_name : str, net_settings : str, computer_name : str):
        self.serial_number = serial_number
        self.friendly_name = friendly_name
        self.net_settings = net_settings
        self.computer_name = computer_name

    def add(self):
        fingerprint = Fingerprint.query.filter_by(serial_number=self.serial_number, friendly_name=self.friendly_name, computer_name=self.computer_name).first()

        if fingerprint is None:
            self.session.add(self)
            self.session.commit()
            
        return fingerprint or self

class NotVerifiedVirus(Model):
    __tablename__ = 'not_verified_viruses'

    hash_id = Column(BigInteger, ForeignKey('hashes.id'))

    def __init__(self, hash_id : int):
        self.hash_id = hash_id

    def add(self):
        not_verified_virus = NotVerifiedVirus.query.filter_by(hash_id=self.hash_id).first()

        if not_verified_virus is None:
            self.session.add(self)
            self.session.commit()

        return not_verified_virus or self

    @staticmethod
    def add_hash(md5 : str = None, sha1 : str = None, sha256 : str = None):
        h = Hash(md5, sha1, sha256).add()
        print("AAAAAAAAAAA", h)
        not_verified_virus = NotVerifiedVirus(h.id).add()
        print("AAAAAAAAAAA", not_verified_virus)
    
class Hash(Model, ElasticsearchMixin):
    __searchable__ = 'elastic_body'
    __tablename__ = 'hashes'
    __table_args__ = (
        CheckConstraint('md5 IS NOT NULL OR sha1 IS NOT NULL OR sha256 IS NOT NULL'),)

    md5 = Column(String(32), nullable=True, unique=True)
    sha1 = Column(String(40), nullable=True, unique=True)
    sha256 = Column(String(64), nullable=True, unique=True)

    elastic_body = ['md5', 'sha1', 'sha256']

    antivirus_info = db.relationship('AVInfo', secondary='hash_associates', backref=db.backref('hashes_info'))
    
    def __init__(self, md5 : str, sha1 : str, sha256 : str) -> None:
        self.md5 = md5
        self.sha1 = sha1
        self.sha256 = sha256

    def add(self):
        # hash = Hash.query.filter_by(md5=self.md5, sha1=self.sha1, sha256=self.sha256).first()
        hash, total = Hash.search(expression=self.md5, fields=['hashes_md5'])

        # print("BBBBBBBB", hash)

        if total == 0:
            self.session.add(self)
            self.session.commit()

        # print("BBBBBBBBBBBB", hash[0] if total > 0 else self)
        return hash[0] if total > 0 else self

class Object(Model, ElasticsearchMixin):
    __searchable__ = 'elastic_body'
    __table_args__ = (UniqueConstraint('path', 'hash_id', 'fingerprint_id', name='uq_file'),)

    fingerprint_id = Column(BigInteger, ForeignKey('fingerprints.id'))
    hash_id = Column(BigInteger, ForeignKey('hashes.id'))
    path = Column(String(1024), nullable=False)
    trusted = Column(SmallInteger, nullable=False, default=0)
    creation_time = Column(String(128), nullable=False)
    last_write_time = Column(String(128), nullable=False)

    elastic_body=['fingerprint_id', 'path', 'hash_id', 'creation_time', 'last_write_time']

    def __init__(self, fingerprint_id: int, path : str, hash_id : str, trusted : int, creation_time : str, last_write_time : str) -> None:
        self.fingerprint_id = fingerprint_id
        self.path = path
        self.hash_id = hash_id
        self.trusted = trusted
        self.creation_time = creation_time
        self.last_write_time = last_write_time
    
    def add(self):
        obj = Object.query.filter_by(path=self.path, hash_id=self.hash_id, fingerprint_id=self.fingerprint_id).first()

        if obj is None:
            self.session.add(self)
            self.session.commit()

        return obj or self

class HashAssociate(Model):

    hash_id = Column(BigInteger, ForeignKey('hashes.id'))
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

    def add(self):
        av_info = AVInfo.query.filter_by(type_description=self.type_description, packer=self.packer, 
            autostart_locations=self.autostart_locations, popular_threat_name=self.popular_threat_name, 
            popular_threat_category=self.popular_threat_category, status=self.status).first()

        if av_info is None:
            self.session.add(self)
            self.session.commit()

        return av_info or self

class VerdictAssociate(Model):

    hash_id = Column(BigInteger, ForeignKey('hashes.id'))
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
        
    def add(self):
        av_verdict = AVVerdict.query.filter_by(category=self.category, engine_name=self.engine_name, 
            engine_version=self.engine_version, result=self.result,
            method=self.method, engine_update=self.engine_update).first()

        if av_verdict is None:
            self.session.add(self)
            self.session.commit()

        return av_verdict or self