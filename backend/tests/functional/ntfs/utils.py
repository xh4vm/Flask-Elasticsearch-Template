import requests
import json
from requests.models import Response
from tests.functional.header import Header
from app.db import db
from tests.utils import random_string


def request_virus_hash(path: str = None, md5_hash: str = None, creation_time: str = None, last_write_time: str = None) -> Response:
    response = requests.post("http://localhost:8000/ntfs/hash", data=json.dumps({
        "path": path or random_string(),
        "md5_hash": md5_hash or "36105BC856519AD14E99DCBAC4F0F622",
        "creation_time": creation_time or random_string(),
        "last_write_time": last_write_time or random_string()
    }), headers=Header.json)

    return response
