FROM python:3.8-buster

RUN apt-get update && apt-get install -y gcc-multilib
RUN useradd poolside

COPY . /poolside
WORKDIR /poolside

RUN make

USER poolside

EXPOSE 9001

ENTRYPOINT ["python3", "poolcgid.py"]
