import requests
import json
from app import celery 
from ..models import Hash, NotVerifiedVirus
from .utils.verdict import Verdict


@celery.task
def get_virustotal_verdict(hash : dict, vt_api_url : str, vt_headers : dict):
    id, md5 = hash.get('id'), hash.get('md5')
    response = requests.get(f"{vt_api_url}/{md5}", headers=vt_headers)

    verdict_data = json.loads(response.text)

    if response.status_code == 404:
        return response.status_code

    if verdict_data.get('data') is not None and verdict_data.get('data').get('attributes') is not None:
        verdict = Verdict(verdict_data)
        verdict.add_analysis_results(hash_id=id)

    return response.status_code
