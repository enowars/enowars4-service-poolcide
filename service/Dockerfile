FROM python:3.8-buster

RUN apt-get update && apt-get install -y gcc-multilib
RUN useradd poolcide

COPY . /poolcide
WORKDIR /poolcide

RUN make clean
RUN make tests
RUN make

USER poolcide

EXPOSE 9001

ENTRYPOINT ["python3", "poolcgid.py"]
