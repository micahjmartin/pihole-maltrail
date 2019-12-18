FROM pihole/pihole:latest

RUN apt update && apt install -y rsyslog

#Set up syslog in the pihole box
RUN echo '*.* action(type="pihole" target="0.0.0.0" port="5151" protocol="tcp")' >> /etc/rsyslog.d/pihole.conf
RUN touch /var/log/pihole/pihole.log && chmod +rw /var/log/pihole/pihole.log
RUN mkdir -p /var/log/ph
RUN sed -i 's:/var/log/pihole.log:/var/log/pihole/pihole.log:g' /etc/dnsmasq.d/01-pihole.conf