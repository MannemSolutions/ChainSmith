FROM python:stretch

WORKDIR /usr/src/app

COPY chainsmith /usr/src/app/chainsmith/
COPY config/chainsmith.yml /etc/chainsmith/chainsmith.yml
COPY requirements.txt setup.py /usr/src/app/
ENV CHAINSMITH_CONFIG /etc/chainsmith/chainsmith.yml

RUN pip install --upgrade pip && pip install --no-cache-dir .

RUN groupadd -r -g 999 chainsmith && useradd -m --no-log-init -r -g chainsmith -u 999 chainsmith

USER 999

ENTRYPOINT ["chainsmith"]
