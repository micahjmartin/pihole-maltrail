FROM pihole/pihole:latest

RUN apt update && apt install -y rsyslog

#Set up syslog in the pihole box
RUN echo '*.* action(type="pihole" target="0.0.0.0" port="5151" protocol="tcp")' >> /etc/rsyslog.d/pihole.conf
RUN mkdir -p /var/log/ph

RUN touch /var/log/ph/pihole.log && chmod +rw /var/log/ph/pihole.log
RUN rm -fr /var/log/pihole.log
RUN ln -s /var/log/ph/pihole.log /var/log/pihole.log
#RUN sed -i 's:/var/log/pihole.log:/var/log/ph/pihole.log:g' /etc/dnsmasq.d/01-pihole.conf
