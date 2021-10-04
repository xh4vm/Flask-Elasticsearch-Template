import json
from typing import Tuple
from ...db import db
from sqlalchemy.orm.scoping import scoped_session
from ..models import AVVerdict, AVInfo, Hash, ObjectAssociate, VerdictAssociate


class Verdict:
    session: scoped_session = db.session

    def __init__(self, verdict_data : dict):
        self.verdict_data = verdict_data
        self.attributes = verdict_data['data']['attributes']

    ## TODO
    def _get_status(self) -> int:
        last_analysis_stats = self.attributes['last_analysis_stats']
        _status = max(last_analysis_stats.values())

        return list(last_analysis_stats.keys())[list(last_analysis_stats.values()).index(_status)]

    def _get_packer(self) -> str:
        return self.attributes['packers'].get('PEiD') if self.attributes.get('packers') is not None else None

    def _popular_threat_classification(self) -> Tuple[str, str]:
        ptc = self.attributes.get('popular_threat_classification')
        result = (None, None)

        if ptc is not None:
            result = ptc.get('popular_threat_category'), ptc.get('popular_threat_name')
            
        return result

    def add_analysis_results(self, hash_id : int) -> None:
        status = getattr(AVInfo, self._get_status().upper())

        if status in [AVInfo.MALICIOUS, AVInfo.SUSPICIOUS]:
            self.add_object_info(hash_id=hash_id)
            self.add_antivirus_results(hash_id=hash_id)

    def add_object_info(self, hash_id : int) -> None:
        popular_threat_category, popular_threat_name = self._popular_threat_classification()
        status = getattr(AVInfo, self._get_status().upper())

        _av_info = AVInfo(type_description=self.attributes.get('type_description'), packer=self._get_packer(), 
            autostart_locations=self.attributes.get('autostart_locations'), creation_date=self.attributes.get('creation_date'),
            popular_threat_category=popular_threat_category, popular_threat_name=popular_threat_name, status=status)
        
        av_info = _av_info.add()

        object_associate = ObjectAssociate(hash_id=hash_id, av_info_id=av_info.id)

        self.session.add(object_associate)
        self.session.commit()

        # d = {}
        # for column in av_info.__table__.columns:
        #     d[column.name] = str(getattr(av_info, column.name))

        # print(d)
        # raise Exception
        
    def add_antivirus_results(self, hash_id : int) -> None:
        analysis_results = self.attributes['last_analysis_results']

        for analyse_result in analysis_results.values():

            _av_verdict = AVVerdict(category=analyse_result['category'], engine_name=analyse_result['engine_name'], 
                engine_version=analyse_result['engine_version'], result=analyse_result['result'], method=analyse_result['method'], 
                engine_update=analyse_result['engine_update'])

            av_verdict = _av_verdict.add()

            verdict_associate = VerdictAssociate(hash_id=hash_id, av_verdict_id=av_verdict.id)

            self.session.add(verdict_associate)
            self.session.commit()

        # ds = []
        # for a in AVVerdict.query.all():
        #     d = {}
        #     for column in a.__table__.columns:
        #         d[column.name] = str(getattr(a, column.name))
        #     ds.append(d)
        # print(ds)
        # raise Exception
