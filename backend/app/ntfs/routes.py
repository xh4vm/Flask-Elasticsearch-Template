import requests
import json
from ..db import db
from flask import jsonify
from sqlalchemy.orm.scoping import scoped_session
from flask_classy import FlaskView, route
from app.decorators import request_validation_required
from .schemas import post_hash_schema
from app.utils.request_type.JSON import JSON
from .models import Object, ObjectInfo, AVVerdict
from .utils.verdict import Verdict


class NTFS(FlaskView):
    session: scoped_session = db.session
    vt_api_url = 'https://www.virustotal.com/api/v3/files'
    vt_headers = {'x-apikey' : 'a13a8e8e39c0b2a66bbd36dc2256467a9e692ca471391fd26a7edd7b1bb1163e'}

    def get(self):
        result = json.loads(Verdict.query.with_entities(Verdict.vt_result).all()[0][0])
        print(result)
        return jsonify(result), 200

    @request_validation_required(schema=post_hash_schema, req_type=JSON)
    @route('/hash/', methods=['POST'])
    def hash(self, validated_request : dict):
        
        object_fs = Object(path=validated_request.get('path'), md5_hash=validated_request.get('md5_hash'),
            creation_time=validated_request.get('creation_time'), last_write_time=validated_request.get('last_write_time'))

        self.session.add(object_fs)
        self.session.commit()

        response = requests.get(f"{self.vt_api_url}/{validated_request.get('md5_hash')}", headers=self.vt_headers)
        verdict_data = json.loads(response.text)
        
        verdict = Verdict(verdict_data)
        verdict.add_object_info(object_id=object_fs.id)

        verdict.add_analysis_results(object_id=object_fs.id)

        return jsonify(), 200
