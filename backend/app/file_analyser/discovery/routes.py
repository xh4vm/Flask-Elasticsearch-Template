import requests
import json
from ...db import db
from flask import jsonify, render_template
from sqlalchemy.orm.scoping import scoped_session
from flask_classy import FlaskView, route
from app.decorators import request_validation_required
from .schemas import post_discovery_schema
from app.utils.request_type.JSON import JSON
from ..models import Hash, NotVerifiedVirus, Object, Fingerprint
from .serializers import serialize_hash
from .celery_task import get_virustotal_verdict


class Discovery(FlaskView):
    session: scoped_session = db.session
    vt_api_url = 'https://www.virustotal.com/api/v3/files'
    vt_headers = {'x-apikey' : 'xxx'}

    
    @request_validation_required(schema=post_discovery_schema, req_type=JSON)
    @route('/discovery/', methods=['POST'])
    def discovery(self, validated_request : dict):

        f = validated_request['fingerprint']
        fingerprint = Fingerprint(serial_number=f.get('serial_number'), computer_name=f.get('computer_name'), 
            net_settings=f.get('net_settings'), friendly_name=f.get('friendly_name')).insert_if_not_exists_and_select()

        h = validated_request['hashes']
        hash = Hash(md5=h.get('md5'), sha1=h.get('sha1'), sha256=h.get('sha256')).insert_if_not_exists_and_select()
        
        Object(fingerprint_id=fingerprint.id, hash_id=hash.id, path=validated_request.get('path'), trusted=validated_request.get('trusted'),
            creation_time=validated_request.get('creation_time'), 
            last_write_time=validated_request.get('last_write_time')).insert_if_not_exists_and_select()
        
        not_verified_virus = NotVerifiedVirus.query.filter_by(hash_id=hash.id).first()

        if not_verified_virus is not None:
            get_virustotal_verdict.delay(hash=serialize_hash(hash), vt_api_url=self.vt_api_url, vt_headers=self.vt_headers)
            not_verified_virus.delete()

        elif not validated_request.get('trusted'):
            get_virustotal_verdict.delay(hash=serialize_hash(hash), vt_api_url=self.vt_api_url, vt_headers=self.vt_headers)
        
        return jsonify(), 202
