ARG BASE_IMAGE
ARG VERSION
FROM ${BASE_IMAGE}:${VERSION}

RUN mkdir /opt/code
WORKDIR /opt/code

COPY ./requirements.txt /opt/code/requirements.txt
COPY ./utils /opt/code
COPY ./src /opt/code/

RUN pip3 install -r requirements.txt