import requests
import json
from app.ntfs.utils.verdict import Verdict
from app.ntfs.models import *
import json

try:
    import uwsgi
    from uwsgidecorators import spool 
    UWSGI = True
    

    def prepare_spooler_args(**kwargs):
        args = {}
        for name, value in kwargs.items():
            args[name.encode('utf-8')] = str(value).encode('utf-8')
        return args

    @spool
    def get_virustotal_verdict(args : dict):
        # try:
        id, md5 = args['id'], args['md5']

        response = requests.get(f"{args['vt_api_url']}/{md5}", headers=json.loads(args['vt_headers']))

        print(response.status_code)
        if response.status_code == 404:
            return uwsgi.SPOOL_OK

        verdict_data = json.loads(response.text)

        verdict = Verdict(verdict_data)
        verdict.add_analysis_results(hash_id=id)


        return uwsgi.SPOOL_OK
        # except:
        #     return uwsgi.SPOOL_RETRY

    @spool
    def add_hash(args : dict):
        h = Hash(args.get('md5'), args.get('sha1'), args.get('sha256')).insert_if_not_exists_and_select()
        not_verified_virus = NotVerifiedVirus(h.id).insert_if_not_exists_and_select()

        return uwsgi.SPOOL_OK

except:
    UWSGI = False

    def get_virustotal_verdict(args : dict):
        id, md5 = args['hash'].get('id'), args['hash'].get('md5')
        response = requests.get(f"{args['vt_api_url']}/{md5}", headers=args['vt_headers'])

        verdict_data = json.loads(response.text)

        verdict = Verdict(verdict_data)
        verdict.add_analysis_results(hash_id=id)

    def add_hash(args : dict):
        h = Hash(args.get('md5'), args.get('sha1'), args.get('sha256')).insert_if_not_exists_and_select()
        not_verified_virus = NotVerifiedVirus(h.id).insert_if_not_exists_and_select()
