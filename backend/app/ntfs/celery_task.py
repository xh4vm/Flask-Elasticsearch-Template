import requests
import json
from app import celery 
from .utils.enrichment.virus_shares import VirusShares
from .models import Hash, NotVerifiedVirus
from .utils.verdict import Verdict


@celery.task
def get_virustotal_verdict(hash : dict, vt_api_url : str, vt_headers : dict):
    id, md5 = hash.get('id'), hash.get('md5')
    response = requests.get(f"{vt_api_url}/{md5}", headers=vt_headers)

    verdict_data = json.loads(response.text)

    if response.status_code == 404:
        return response.status_code

    verdict = Verdict(verdict_data)
    verdict.add_analysis_results(hash_id=id)

    return response.status_code

@celery.task
def add_virus_hash(link_page : str):
    hashes = VirusShares.get_hash_from_page(link_page)

    for md5 in hashes:
        hash = Hash(md5=md5).insert_if_not_exists_and_select()
        not_verified_virus = NotVerifiedVirus(hash_id=hash.id).insert_if_not_exists_and_select()