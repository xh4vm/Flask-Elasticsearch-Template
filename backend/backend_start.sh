#!/bin/sh
flask db init
flask db migrate
flask db upgrade

# /etc/init.d/redis-server restart 
# celery -A celery_worker.celery worker &

service nginx start
uwsgi --ini uwsgi.ini

# Только для процесса разработки!
# Изменение кода будет инициировать перезагрузку сервиса
# python3 malware_analyse.py --port 5000 --host 0.0.0.0

# Deploy version
# exec gunicorn -b :5000 --access-logfile - --error-logfile - justbegin:app