FROM postgres:latest

WORKDIR /malware_analyse
COPY db_start.sh ./

RUN apt-get update && apt-get -y install redis

RUN chmod +x db_start.sh

EXPOSE 5432
ENTRYPOINT [ "./db_start.sh" ]