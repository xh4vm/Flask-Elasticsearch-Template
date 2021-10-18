import requests
import json
from app import celery 
from .utils.virus_shares import VirusShares
from ..models import Hash, NotVerifiedVirus


@celery.task
def add_virus_hash(link_page : str):
    hashes = VirusShares.get_hash_from_page(link_page)

    for md5 in hashes:
        hash = Hash(md5=md5).insert_if_not_exists_and_select()
        not_verified_virus = NotVerifiedVirus(hash_id=hash.id).insert_if_not_exists_and_select()
