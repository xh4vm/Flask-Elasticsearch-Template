import requests
import json
from ..db import db
from flask import jsonify
from sqlalchemy.orm.scoping import scoped_session
from sqlalchemy.sql import func
from flask_classy import FlaskView, route
from app.decorators import request_validation_required
from .schemas import post_hash_schema
from app.utils.request_type.JSON import JSON
from .models import Hash, Object, AVInfo, AVVerdict, Fingerprint
from .serializers import serialize_hash
from .tasks import get_virustotal_verdict


class NTFS(FlaskView):
    session: scoped_session = db.session
    vt_api_url = 'https://www.virustotal.com/api/v3/files'
    vt_headers = {'x-apikey' : 'a13a8e8e39c0b2a66bbd36dc2256467a9e692ca471391fd26a7edd7b1bb1163e'}

    def get(self):
        object = Object.query.all()
        object_info = AVInfo.query.all()
        analysis = AVVerdict.query.all()

        return jsonify({"object": object, "object_info": object_info, "analysis": analysis}), 200

    @request_validation_required(schema=post_hash_schema, req_type=JSON)
    @route('/hash/', methods=['POST'])
    def hash(self, validated_request : dict):
        
        f = validated_request['fingerprint']
        fingerprint = Fingerprint(serial_number=f.get('serial_number'), computer_name=f.get('computer_name'), 
            net_settings=f.get('net_settings'), friendly_name=f.get('friendly_name')).add()

        h = validated_request['hashes']
        hash = Hash(md5=h.get('md5'), sha1=h.get('sha1'), sha256=h.get('sha256'))
        # hash = _hash.add()
        self.session.add(hash)
        self.session.commit()

        Object(fingerprint_id=fingerprint.id, hash_id=hash.id, path=validated_request.get('path'),
            creation_time=validated_request.get('creation_time'), last_write_time=validated_request.get('last_write_time')).add()

        # get_virustotal_verdict(hash=serialize_hash(hash), vt_api_url=self.vt_api_url, vt_headers=self.vt_headers)
        
        # loop.run_forever(
        # get_virustotal_verdict(hash=serialize_hash(hash), vt_api_url=self.vt_api_url, vt_headers=self.vt_headers)
        # )
        
        task = get_virustotal_verdict.delay(hash=serialize_hash(hash), vt_api_url=self.vt_api_url, vt_headers=self.vt_headers)
        result = task.wait(timeout=None, interval=0.5)
        
        print(result)
        raise Exception
        return jsonify(), 202
