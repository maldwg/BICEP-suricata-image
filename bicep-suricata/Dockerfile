ARG BASE_IMAGE
ARG VERSION
FROM ${BASE_IMAGE}:${VERSION}

RUN apt install python3-pip -y

RUN mkdir /opt/code
WORKDIR /opt/code

COPY ./requirements.txt /opt/code/requirements.txt
COPY ./src/ /opt/code/src
COPY ./apt-requirements.txt /tmp/apt-requirements.txt

RUN pip3 install -r requirements.txt
RUN xargs apt install -y < /tmp/apt-requirements.txt


# path to locate the IDSBase implementation
ENV IDS_MODULE=src.models.suricata
ENV IDS_CLASS=Suricata

CMD [ "/bin/bash","-c","fastapi dev /opt/code/src/main.py --host 0.0.0.0 --port ${PORT}" ]