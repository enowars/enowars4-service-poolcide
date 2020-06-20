FROM python:3.8-buster

RUN apt-get update && apt-get install -y gcc-multilib

COPY . /poolside
WORKDIR /poolside

USER poolside

EXPOSE 9001

ENTRYPOINT ["make", "run"]

