FROM debian:jessie

RUN apt-get update \ 
    && apt-get upgrade -y \
    && apt-get install -y python3 python3-dev python3-pip

RUN apt-get install -y libpcap-dev

RUN pip3 install pcapy

RUN mkdir /root/maltrail
WORKDIR /root/maltrail

COPY ./ ./

RUN python3 /root/maltrail/core/update.py

RUN echo "python3 /root/maltrail/sensor.py &" >> /root/run.sh
#RUN echo "python3 /root/maltrail/server.py" >> /root/run.sh
RUN echo "python3 /root/maltrail/pihole.py" >> /root/run.sh

ENTRYPOINT  ["/bin/bash", "/root/run.sh"]
