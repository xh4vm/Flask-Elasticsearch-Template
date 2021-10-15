import requests
import json
from ..db import db
from flask import jsonify, render_template
from sqlalchemy.orm.scoping import scoped_session
from sqlalchemy.sql import func
from flask_classy import FlaskView, route
from app.decorators import request_validation_required
from .decorators import fingerprint_required, object_required
from .schemas import post_hash_schema
from app.utils.request_type.JSON import JSON
from .models import Hash, Object, AVInfo, AVVerdict, Fingerprint, HashAssociate, VerdictAssociate, NotVerifiedVirus
from .serializers import serialize_hash
from .tasks import get_virustotal_verdict, add_hash
from sqlalchemy.sql.expression import null
from itertools import chain
from .utils.enrichment.virus_shares import VirusShares

try:
    from .tasks import prepare_spooler_args
except:
    pass


class NTFS(FlaskView):
    session: scoped_session = db.session
    vt_api_url = 'https://www.virustotal.com/api/v3/files'
    vt_headers = {'x-apikey' : 'a13a8e8e39c0b2a66bbd36dc2256467a9e692ca471391fd26a7edd7b1bb1163e'}

    def get(self):

        # print(len([h.md5 for h in Hash.query.filter(NotVerifiedVirus.hash_id == Hash.id).all()]))

        fingerprint_data = (Fingerprint.query
            .with_entities(*Fingerprint.__table__.columns, func.count(Object.id).label('count_objects'))
            .filter(Fingerprint.id == Object.fingerprint_id)
            .group_by(Fingerprint.id)
            .all())
        
        return render_template("ntfs/index.html", fingerprint_data=fingerprint_data), 200

    @fingerprint_required
    @route('/<int:fingerprint_id>/', methods=['GET'])
    def by_fingerprint(self, fingerprint : Fingerprint):
        objects_with_status = (Object
                    .query
                    .with_entities(*Object.__table__.columns, Hash.md5, Hash.sha1, Hash.sha256, AVInfo.status)
                    .filter(Object.fingerprint_id == fingerprint.id, Hash.id == Object.hash_id, AVInfo.id == HashAssociate.av_info_id,
                        HashAssociate.hash_id == Object.hash_id))

        objects = (Object
                    .query
                    .with_entities(*Object.__table__.columns, Hash.md5, Hash.sha1, Hash.sha256, null().label('status'))
                    .filter(
                        Object.fingerprint_id == fingerprint.id, Hash.id == Object.hash_id,
                        ~Object.hash_id.in_(
                            chain(*self.session.query(HashAssociate.hash_id).all())
                        )
                    )
                    .union(objects_with_status)
                    .all())

        return render_template("ntfs/host.html", objects=objects), 200

    @fingerprint_required
    @object_required
    @route('/<int:fingerprint_id>/<int:object_id>/', methods=['GET'])
    def by_object(self, fingerprint : Fingerprint, object : Object):
        av_info = (AVInfo.query
            .filter(AVInfo.id == HashAssociate.av_info_id, HashAssociate.hash_id == object.hash_id)
            .first())
        
        av_verdict = (AVVerdict.query
            .filter(AVVerdict.id == VerdictAssociate.av_verdict_id, VerdictAssociate.hash_id == object.hash_id)
            .order_by(AVVerdict.category)
            .all())

        return render_template("ntfs/object/index.html", object=object, av_info=av_info, av_verdict=av_verdict), 200

    @request_validation_required(schema=post_hash_schema, req_type=JSON)
    @route('/hash/', methods=['POST'])
    def hash(self, validated_request : dict):

        f = validated_request['fingerprint']
        fingerprint = Fingerprint(serial_number=f.get('serial_number'), computer_name=f.get('computer_name'), 
            net_settings=f.get('net_settings'), friendly_name=f.get('friendly_name')).insert_if_not_exists_and_select()

        h = validated_request['hashes']
        hash = Hash(md5=h.get('md5'), sha1=h.get('sha1'), sha256=h.get('sha256')).insert_if_not_exists_and_select()
        
        Object(fingerprint_id=fingerprint.id, hash_id=hash.id, path=validated_request.get('path'), trusted=validated_request.get('trusted'),
            creation_time=validated_request.get('creation_time'), 
            last_write_time=validated_request.get('last_write_time')).insert_if_not_exists_and_select()
        
        args = prepare_spooler_args(
                id=hash.id, md5=hash.md5, vt_api_url=self.vt_api_url, vt_headers=json.dumps(self.vt_headers))

        not_verified_virus = NotVerifiedVirus.query.filter_by(hash_id=hash.id).first()

        if not_verified_virus is not None:
            get_virustotal_verdict.spool(args)
            not_verified_virus.delete()

        elif not validated_request.get('trusted'):
            get_virustotal_verdict.spool(args)

        return jsonify(), 202

    @route('/hash/enrichment/virus_shares/', methods=['GET'])
    def get_hashes_virus_shares(self):
        virus_shares = VirusShares()

        link_pages = virus_shares.get_link_pages()

        for link_page in link_pages:
            hashes = virus_shares.get_hash_from_page(link_page)

            for md5 in hashes:
                args = prepare_spooler_args(md5=md5)
                add_hash(args)
                # add_hash.spool(args)
                # NotVerifiedVirus.add_hash(md5=md5)

        return {"status": True}, 200
