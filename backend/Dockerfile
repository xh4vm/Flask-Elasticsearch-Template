FROM python:3.6
# FROM python:3.9.6
# FROM python:3.8

RUN apt-get update && apt-get install -y nginx python3-pip build-essential postgresql postgresql-client python3-dev

WORKDIR /malware_analyse

RUN pip3 install --upgrade pip

COPY nginx.conf /etc/nginx
COPY app app
COPY tests tests
COPY requirements.txt malware_analyse.py celery_worker.py config.py pytest.ini backend_start.sh uwsgi.ini ./

RUN chmod +x backend_start.sh

ENV FLASK_APP malware_analyse.py

RUN pip3 install -r requirements.txt

EXPOSE 5000
ENTRYPOINT [ "./backend_start.sh" ]