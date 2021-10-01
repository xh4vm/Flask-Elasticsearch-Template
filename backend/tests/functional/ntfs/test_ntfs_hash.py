import json
from flask import request
from tests.functional.bases.base import BaseTestCase
from tests.functional.header import Header
from tests.utils import random_string


class UserGetTestCase(BaseTestCase):

    def test_ntfs_nash_virus_success(self):

        with self.app.test_client() as test_client:
            response = test_client.post(f'/ntfs/hash/', data=json.dumps({
                "path": random_string(), 
                "md5_hash": "1e4de74f23fdb44ca1abc2f9838ffd0c ", 
                "creation_time": random_string(), 
                "last_write_time": random_string()}), headers=Header.json)
            assert response.status_code == 200
    