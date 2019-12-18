FROM pihole/pihole:latest

RUN apt update && apt install -y rsyslog

#Set up syslog in the pihole box
RUN echo '*.* action(type="pihole" target="0.0.0.0" port="5151" protocol="tcp")' >> /etc/rsyslog.d/pihole.conf
RUN touch /var/log/pihole.log && chmod +rw /var/log/pihole.log