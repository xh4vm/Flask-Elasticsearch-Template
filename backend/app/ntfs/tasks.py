from flask import current_app
import requests
import json
from app import celery 
from .models import Hash
from .utils.verdict import Verdict
from ..db import db


@celery.task
def get_virustotal_verdict(hash : dict, vt_api_url : str, vt_headers : str):
    with current_app.test_request_context():
        with current_app.app_context():
            db.session.commit()

            id, md5 = hash.get('id'), hash.get('md5')
            response = requests.get(f"{vt_api_url}/{md5}", headers=vt_headers)

            verdict_data = json.loads(response.text)
            
            verdict = Verdict(verdict_data)
            verdict.add_analysis_results(hash_id=id)

            return Hash.query.all()