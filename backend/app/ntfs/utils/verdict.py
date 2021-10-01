import json
from typing import Tuple
from ...db import db
from sqlalchemy.orm.scoping import scoped_session
from ..models import AVVerdict, AVInfo


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

    def add_av_info(self) -> None:
        popular_threat_category, popular_threat_name = self._popular_threat_classification()

        av_info = AVInfo( type_description=self.attributes.get('type_description'), packer=self._get_packer(), 
            autostart_locations=self.attributes.get('autostart_locations'), creation_date=self.attributes.get('creation_date'),
            names=self.attributes.get('names'), popular_threat_category=popular_threat_category,
            popular_threat_name=popular_threat_name, status=getattr(AVInfo, self._get_status().upper()))
        
        self.session.add(av_info)
        self.session.commit()

    def add_analysis_results(self) -> None:
        analysis_results = self.attributes['last_analysis_results']

        for analyse_result in analysis_results.values():

            av_verdict = AVVerdict(category=analyse_result['category'], engine_name=analyse_result['engine_name'], 
                engine_version=analyse_result['engine_version'], result=analyse_result['result'], method=analyse_result['method'], 
                engine_update=analyse_result['engine_update'])

            self.session.add(av_verdict)
            self.session.commit()
