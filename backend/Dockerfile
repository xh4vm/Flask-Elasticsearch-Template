FROM python:3.8

RUN apt-get update && apt-get install -y python3-pip python-dev build-essential redis postgresql postgresql-client gcc python3-dev musl-dev
RUN pip install --upgrade pip

WORKDIR /socinf

COPY app app
COPY tests tests
COPY requirements.txt socinf.py celery_worker.py config.py pytest.ini backend_start.sh ./

RUN chmod +x backend_start.sh

ENV FLASK_APP socinf.py

RUN pip3 install -r requirements.txt

EXPOSE 5000
ENTRYPOINT [ "./backend_start.sh" ]