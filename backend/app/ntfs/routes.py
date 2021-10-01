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
from .models import Object, AVInfo, AVVerdict, Fingerprint
from .utils.verdict import Verdict


class NTFS(FlaskView):
    session: scoped_session = db.session
    vt_api_url = 'https://www.virustotal.com/api/v3/files'
    vt_headers = {'x-apikey' : 'a13a8e8e39c0b2a66bbd36dc2256467a9e692ca471391fd26a7edd7b1bb1163e'}

    def get(self):
        # object_fs = Object.query.all()
        av_info = AVInfo.query.all()
        # av_verdict = AVVerdict.query.all()
        # print({"object_fs": object_fs, "object_info": object_info, "av_verdict": av_verdict})
        
        # data = ObjectInfo.query.with_entities(
        #     *Fingerprint.__table__.columns,
        #     func.count(ObjectInfo.status)
        # ).filter(
        #     Fingerprint.id == Object.fingerprint_id,
        #     ObjectInfo.object_id == Object.id,
        #     ObjectInfo.status == ObjectInfo.MALICIOUS
        # ).group_by(Fingerprint.id).all()

        # print(data)
        print(len(av_info))

        # print(ObjectInfo.query.with_entities(ObjectInfo.status).all())

        return jsonify(), 200

    @request_validation_required(schema=post_hash_schema, req_type=JSON)
    @route('/hash/', methods=['POST'])
    def hash(self, validated_request : dict):
        
        f = validated_request['fingerprint']
        fingerprint = Fingerprint(f.get('serial_number'), f.get('computer_name'), f.get('net_settings'), f.get('friendly_name'))
        fingerprint.add()

        object_fs = Object(fingerprint_id=fingerprint.id, path=validated_request['path'], md5_hash=validated_request['md5_hash'],
            creation_time=validated_request['creation_time'], last_write_time=validated_request['last_write_time'])

        self.session.add(object_fs)
        self.session.commit()

        response = requests.get(f"{self.vt_api_url}/{validated_request.get('md5_hash')}", headers=self.vt_headers)
        # response = requests.get(f"{self.vt_api_url}/{object_fs.md5_hash}", headers=self.vt_headers)
        verdict_data = json.loads(response.text)
        print(verdict_data)
        verdict = Verdict(verdict_data)
        
        verdict.add_object_info()

        verdict.add_analysis_results()

        return jsonify(), 200
