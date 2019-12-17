FROM python:3-alpine

RUN apk update && apk add g++ libpcap-dev git

COPY requirements.txt .
RUN pip3 install -r requirements.txt

RUN git clone https://github.com/stamparm/maltrail /opt/maltrail
WORKDIR /opt/maltrail

COPY entrypoint.sh .
COPY pihole.py .

ENTRYPOINT  ["/bin/sh", "entrypoint.sh"]
