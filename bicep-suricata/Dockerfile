ARG BASE_IMAGE
ARG VERSION
FROM ${BASE_IMAGE}:${VERSION}

RUN apt install python3-pip -y
RUN rm /usr/lib/python3.12/EXTERNALLY-MANAGED 

RUN mkdir /opt/code
WORKDIR /opt/code

COPY ./requirements.txt /opt/code/requirements.txt
COPY ./utils /opt/code
COPY ./src /opt/code/

RUN pip3 install -r requirements.txt

# TODO: start command to be like in the docer compose that he needs variable port for startup
# TODO: add to core that the core is indeed a variable passed to the container
# TODO: inject environment variables into the container/image