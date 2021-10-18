import json
from sqlalchemy.orm import relationship
from sqlalchemy.sql.sqltypes import String, Integer, BigInteger, SmallInteger
from sqlalchemy.sql.schema import CheckConstraint, Column, UniqueConstraint, ForeignKey
from ..db import Model, db
from ..db.elasticsearch.mixin import ElasticsearchMixin
import re
from .utils.hash_handler.md5_handler import MD5Handler
from .utils.hash_handler.sha1_handler import SHA1Handler
from .utils.hash_handler.sha256_handler import SHA256Handler


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

    def insert_if_not_exists_and_select(self):
        fingerprint = Fingerprint.query.filter_by(serial_number=self.serial_number, friendly_name=self.friendly_name, computer_name=self.computer_name).first()

        if fingerprint is None:
            self.session.add(self)
            self.session.commit()
            
        return fingerprint or self


class Object(Model, ElasticsearchMixin):
    __searchable__ = 'elastic_body'
    __table_args__ = (UniqueConstraint('path', 'hash_id', 'fingerprint_id', name='uq_file'),)

    fingerprint_id = Column(BigInteger, ForeignKey('fingerprints.id'))
    hash_id = Column(BigInteger, ForeignKey('object_hashes.id'))
    path = Column(String(1024), nullable=False)
    trusted = Column(SmallInteger, nullable=False, default=0)
    creation_time = Column(String(128), nullable=False)
    last_write_time = Column(String(128), nullable=False)

    hash = relationship('Hash', backref=db.backref('object'))
    elastic_body=['path', 'creation_time', 'last_write_time']

    def __init__(self, fingerprint_id: int, path : str, hash_id : str, trusted : int, creation_time : str, last_write_time : str) -> None:
        self.fingerprint_id = fingerprint_id
        self.path = path
        self.hash_id = hash_id
        self.trusted = trusted
        self.creation_time = creation_time
        self.last_write_time = last_write_time
    
    def insert_if_not_exists_and_select(self):
        obj = Object.query.filter_by(path=self.path, hash_id=self.hash_id, fingerprint_id=self.fingerprint_id).first()

        if obj is None:
            self.session.add(self)
            self.session.commit()

        return obj or self

class NotVerifiedVirus(Model):
    __tablename__ = 'not_verified_viruses'

    hash_id = Column(BigInteger, ForeignKey('object_hashes.id'))

    def __init__(self, hash_id : int):
        self.hash_id = hash_id

    def insert_if_not_exists_and_select(self):
        not_verified_virus = NotVerifiedVirus.query.filter_by(hash_id=self.hash_id).first()

        if not_verified_virus is None:
            self.session.add(self)
            self.session.commit()

        return not_verified_virus or self
    

class Hash(Model, ElasticsearchMixin):
    __searchable__ = 'elastic_body'
    __tablename__ = 'object_hashes'
    __table_args__ = (
        CheckConstraint("md5 != '' OR sha1 != '' OR sha256 != ''", name='check_object_hash'),
        UniqueConstraint('md5', 'sha1', 'sha256', name='uq_object_hash'),)

    md5 = Column(String(32), nullable=False)
    sha1 = Column(String(40), nullable=False)
    sha256 = Column(String(64), nullable=False)

    elastic_body = ['md5', 'sha1', 'sha256']

    antivirus_info = db.relationship('AVInfo', secondary='hash_associates', backref=db.backref('hashes_info'))
    
    def __init__(self, md5 : str = None, sha1 : str = None, sha256 : str = None) -> None:
        self.md5 = MD5Handler(md5).get()
        self.sha1 = SHA1Handler(sha1).get()
        self.sha256 = SHA256Handler(sha256).get()

    @property
    def __should__(self):
        _should = []
        
        if self.md5 != "":
            _should.append({"match": {"md5": self.md5}})

        if self.sha1 != "":
            _should.append({"match": {"sha1": self.sha1}})

        if self.sha256 != "":
            _should.append({"match": {"sha256": self.sha256}})
        
        return _should

    def insert_if_not_exists_and_select(self):
        query = {
            "query": {
                "bool": {
                    "must": self.__should__
                }
            }
        }
        
        hash = Hash.raw_search_one(body=query)
        
        # print("AAAAAAAAAAA", hash, self.md5)

        if hash is None:
            self.session.add(self)
            self.session.commit()
            return self

        return hash


class HashAssociate(Model):

    hash_id = Column(BigInteger, ForeignKey('object_hashes.id'))
    av_info_id = Column(BigInteger, ForeignKey('av_infos.id'))
