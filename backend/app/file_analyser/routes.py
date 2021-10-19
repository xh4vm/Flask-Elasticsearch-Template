from app import redis_client
import requests
import json
from ..db import db
from flask import jsonify, render_template, request, send_file
from sqlalchemy.orm.scoping import scoped_session
from sqlalchemy.sql import func
from flask_classy import FlaskView, route
from app.decorators import request_validation_required
from .decorators import fingerprint_required, object_required, search_type_optional
from app.utils.request_type.JSON import JSON
from app.utils.request_type.Args import Args
from .models import Object, Fingerprint
from .discovery.models import AVInfo, AVVerdict, VerdictAssociate
from .models import Hash, HashAssociate, NotVerifiedVirus
from sqlalchemy.sql.expression import null
from itertools import chain
from .schemas import post_search_schema, get_search_schema
from typing import Optional
from base64 import b64decode


class FileAnalyser(FlaskView):
    session: scoped_session = db.session
    agent_root_path = "file_analyser/agents"
    
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
    @route('/<int:fingerprint_id>/', methods=['GET'])
    def by_fingerprint(self, fingerprint : Fingerprint):
        per_page = 10
        page = request.args.get('page', 1, type=int)
        search_type = redis_client.get('search_type').decode() if redis_client.get('search_type') else "best_fields"

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

        return render_template("file_analyser/host/index.html", objects=objects, fingerprint_id=fingerprint.id, search_type=search_type), 200

    @fingerprint_required
    @request_validation_required(schema=get_search_schema, req_type=Args)
    @route('/<int:fingerprint_id>/search/', methods=['GET'])
    def by_fingerprint_search(self, fingerprint : Fingerprint, validated_request : dict):
        per_page = 10
        page = request.args.get('page', 1, type=int)
        
        search_type = validated_request['search_type']
        search_obj = json.loads(b64decode(validated_request['search_obj']))

        redis_client.set('search_type', search_type)

        _hash_result_search, th = Hash.search(expression=validated_request['s'], search_type=search_type)
        _av_info_search, ti = AVInfo.search(expression=validated_request['s'], search_type=search_type)
        _av_verdict_search, tv = AVVerdict.search(expression=validated_request['s'], search_type=search_type)

        result_search, to = Object.search_ids(expression=validated_request['s'], search_type=search_type)
        result_search.extend(list(chain(*[[o.id for o in h.object] for h in _hash_result_search])))
        
        result_search.extend([o.id for o in 
            chain(*[h.object for h in 
            chain(*[a.hashes for a in _av_info_search])])])

        result_search.extend([o.id for o in 
            chain(*[h.object for h in 
            chain(*[a.hashes for a in _av_verdict_search])])])

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

        return render_template("file_analyser/host/index.html", objects=objects, fingerprint_id=fingerprint.id, search_type=search_type), 200

    @route('/settings/', methods=['GET'])
    def settings(self):
        return render_template("file_analyser/settings.html"), 200

    @route('/settings/download/agent/<os>/<type_file>/', methods=['GET'], defaults={'arch': None})
    @route('/settings/download/agent/<os>/<type_file>/<arch>/', methods=['GET'])
    def download_agent(self, os : str, type_file : str, arch : str = None):

        if os == 'windows':
            if type_file == "powershell":
                return send_file(f"{self.agent_root_path}/windows/agent.ps1", as_attachment=True)

            elif type_file == "exe":

                if arch == "x86":
                    return send_file(f"{self.agent_root_path}/windows/agent_x86.exe", as_attachment=True)
                elif arch == "x64": 
                    return send_file(f"{self.agent_root_path}/windows/agent_x64.exe", as_attachment=True)
                else:
                    return jsonify(), 400
            else:
                return jsonify(), 400

        elif os == 'linux':

            if type_file == "bash":
                return send_file(f"{self.agent_root_path}/linux/agent.sh", as_attachment=True)

            elif type_file == "elf":
                return send_file(f"{self.agent_root_path}/linux/agent", as_attachment=True)

            else:
                return jsonify(), 400
        else:
            return jsonify(), 400
    