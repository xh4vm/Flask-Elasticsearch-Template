import requests
import json
from ...db import db
from flask import jsonify, render_template, redirect
from sqlalchemy.orm.scoping import scoped_session
from flask_classy import FlaskView, route
from .utils.virus_shares import VirusShares
from .celery_task import add_virus_hash
from app import redis_client
from app.decorators import request_validation_required
from .schemas import post_enrichment_check_schema
from app.utils.request_type.JSON import JSON


class Enrichment(FlaskView):
    session: scoped_session = db.session

    @route('/enrichment/virus_shares/', methods=['POST'])
    def start_enrichment_cirus_shares(self):
        old_tasks = redis_client.get('virus_shares_tasks')

        if old_tasks is not None and type(old_tasks) == dict and 'PENDING' in old_tasks.values():
            return redirect('/file_analyser/enrichment/virus_shares/', code=303)

        link_pages = VirusShares.get_link_pages()

        tasks = {}
        for link_page in link_pages:
            task = add_virus_hash.delay(link_page=link_page)
            tasks[task.id] = task.state

        redis_client.set('virus_shares_tasks', json.dumps(tasks))

        return redirect('/file_analyser/enrichment/virus_shares/', code=303)

    @route('/enrichment/virus_shares/', methods=['GET'])
    def get_hashes_virus_shares(self, ):
        _tasks = redis_client.get('virus_shares_tasks')
        tasks = json.loads(_tasks) if _tasks is not None else {}
        return render_template('file_analyser/enrichment/index.html', tasks=tasks), 200

    @route('/enrichment/virus_shares/check/', methods=["POST"])
    def check_task_status(self):
        _tasks = redis_client.get('virus_shares_tasks')
        tasks = json.loads(_tasks) if _tasks is not None else {}

        for task_id in tasks.keys():
            task = add_virus_hash.AsyncResult(task_id)

            if task.state == 'PENDING': 
                tasks[task_id] = 'PENDING'
            
            elif task.state != 'FAILURE':
                tasks[task_id] = task.state

            elif task.state == 'FAILURE':
                print(task)
                # tasks[task_id] = task.state
            
            else:
                tasks[task_id] = task.state
        
        redis_client.set('virus_shares_tasks', json.dumps(tasks))

        return jsonify(tasks), 200