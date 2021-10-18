import requests
import json
from ..db import db
from flask import jsonify, render_template, request
from sqlalchemy.orm.scoping import scoped_session
from sqlalchemy.sql import func
from flask_classy import FlaskView, route
from app.decorators import request_validation_required
from .decorators import fingerprint_required, object_required
from app.utils.request_type.JSON import JSON
from .models import Object, Fingerprint
from .discovery.models import AVInfo, AVVerdict,VerdictAssociate
from .models import Hash, HashAssociate, NotVerifiedVirus
from sqlalchemy.sql.expression import null
from itertools import chain
from .schemas import post_search_schema


class FileAnalyser(FlaskView):
    session: scoped_session = db.session
    
    def get(self):

        # print(len(Hash.query.filter(Hash.id == NotVerifiedVirus.hash_id).all()))

        per_page = 10
        page = request.args.get('page', 1, type=int)

        fingerprint_data = (Fingerprint.query
            .with_entities(*Fingerprint.__table__.columns, func.count(Object.id).label('count_objects'))
            .filter(Fingerprint.id == Object.fingerprint_id)
            .group_by(Fingerprint.id)
            .paginate(page, per_page))


        return render_template("file_analyser/index.html", fingerprint_data=fingerprint_data), 200

    @route('/settings/', methods=['GET'])
    def settings(self):

        return render_template("file_analyser/settings.html"), 200

    @fingerprint_required
    @route('/<int:fingerprint_id>/', methods=['GET'])
    def by_fingerprint(self, fingerprint : Fingerprint):
        per_page = 10
        page = request.args.get('page', 1, type=int)

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
                    .paginate(page, per_page))

        return render_template("file_analyser/host/index.html", objects=objects, fingerprint_id=fingerprint.id), 200

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

        return render_template("file_analyser/object/index.html", object=object, av_info=av_info, av_verdict=av_verdict), 200

    @fingerprint_required
    @request_validation_required(schema=post_search_schema)
    @route('/<int:fingerprint_id>/', methods=['POST'])
    def by_fingerprint_search(self, fingerprint : Fingerprint, validated_request : dict):
        per_page = 10
        page = request.args.get('page', 1, type=int)

        _hash_result_search, th = Hash.search(expression=validated_request['s'])

        result_search, to = Object.search_ids(expression=validated_request['s'])
        result_search.extend(chain(*[[o.id for o in h.object] for h in _hash_result_search]))

        objects_with_status = (Object
                    .query
                    .with_entities(*Object.__table__.columns, Hash.md5, Hash.sha1, Hash.sha256, AVInfo.status)
                    .filter(
                        Object.fingerprint_id == fingerprint.id, 
                        Hash.id == Object.hash_id, 
                        AVInfo.id == HashAssociate.av_info_id,
                        HashAssociate.hash_id == Object.hash_id, 
                        Object.id.in_(result_search)))

        objects = (Object
                    .query
                    .with_entities(*Object.__table__.columns, Hash.md5, Hash.sha1, Hash.sha256, null().label('status'))
                    .filter(
                        Object.fingerprint_id == fingerprint.id, Hash.id == Object.hash_id,
                        ~Object.hash_id.in_(
                            chain(*self.session.query(HashAssociate.hash_id).all())
                        ),
                        Object.id.in_(result_search)
                    )
                    .union(objects_with_status)
                    .paginate(page, per_page))

        return render_template("file_analyser/host/index.html", objects=objects, fingerprint_id=fingerprint.id), 200