FROM python:3.8-buster
LABEL maintainer="ENOFLAG <mail@enoflag.de>"

# Install python3 and uswgi
RUN apt-get update && apt-get install -y git

# copy our files in.
WORKDIR /checker
RUN wget https://github.com/FiloSottile/age/releases/download/v1.0.0-beta2/age-v1.0.0-beta2-linux-amd64.tar.gz \
    && tar -xvf age-v1.0.0-beta2-linux-amd64.tar.gz \
    && mv ./age ./age_dir && mv ./age_dir/age ./age && rm -rf ./age_dir \
    && rm -rf age-*

COPY ./requirements.txt /checker/requirements.txt
RUN pip3 install -r requirements.txt
COPY . .

ENTRYPOINT [ "gunicorn", "-c", "gunicorn.conf.py", "checker:app" ]
