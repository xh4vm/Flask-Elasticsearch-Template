import json
from tests.functional.bases.base import BaseTestCase
from tests.functional.header import Header
from tests.utils import random_string
from time import sleep
from app.ntfs.models import *
import requests


class NTFSHashTestCase(BaseTestCase):
    pass
    
    # def test_virus_check_success(self):

    #     with self.app.test_client() as test_client:
    #         response = test_client.post("/ntfs/hash/", data=json.dumps({
    #             "fingerprint": {
    #                 "serial_number": random_string(), "friendly_name": random_string(), 
    #                 "computer_name": random_string(), "net_settings": random_string()},
    #             "path": random_string(),
    #             "hashes": {"md5": "290a285b1376a9366467124b76646f46"},
    #             "creation_time": random_string(),
    #             "last_write_time": random_string()
    #         }), headers=Header.json)

    #         sleep(5)

    #         print(Hash.query.all())
    #         print(Object.query.all())
    #         print(ObjectAssociate.query.all())
    #         print(AVInfo.query.all())
    #         print(AVVerdict.query.all())
    #         print(VerdictAssociate.query.all())

    #         raise Exception

    #         assert response.status_code == 202
    
    # def test_legit_check_success(self):

    #     with self.app.test_client() as test_client:
    #         response = test_client.post("/ntfs/hash/", data=json.dumps({
    #             "fingerprint": {
    #                 "serial_number": random_string(), "friendly_name": random_string(), 
    #                 "computer_name": random_string(), "net_settings": random_string()},
    #             "path": random_string(),
    #             "hashes": {"md5": "a976339058116fcf346437d797c7eec1"},
    #             "creation_time": random_string(),
    #             "last_write_time": random_string()
    #         }), headers=Header.json)

    #         assert response.status_code == 202
