import socketserver
import socket
import threading
import os
import datetime
import re


from core.log import log_event

from core.settings import config
from core.settings import CONFIG_FILE
from core.settings import read_config

# Tell malshare the source of the log

FORMAT_NAME="PiHole"
PIHOLE_IP=""
# 


class Event(object):
    """This class represents an event that is in the form of a
    dnsmasq log format
    """
    def __init__(self, log):
        self.log = log
        

class LogServer(socketserver.BaseRequestHandler):
    def handle(self):
        while self.request:
            try:
                data = self.readline()
                if b"query[" in data:
                    # Read the next line too
                    data += self.readline()
                    data = data.decode("utf-8")
                    event_tuple = self.parse_log(data)
                    if event_tuple:
                        print("[*] PiHole blocked '{}' for {}".format(event_tuple[8], event_tuple[2]))
                        log_event(event_tuple)
                if not data:
                    continue
            except socket.error as E:
                print("[!]", E)
                return
    
    def readline(self):
        _buf = self.request.recv(1)
        data = _buf
        while _buf and _buf != b"\n":
            _buf = self.request.recv(1)
            data += _buf
            if _buf == b"\n":
                break
        return data
    
    def parse_log(self, log):
        """Parse a log file and return the date, type, and domain of the log"""
        log = log.split("\n")
        # Check to see if the first line is a query
        reg_type = r"(.*)dnsmasq\[.*\]: query.*from (.*)"
        res = re.search(reg_type, log[0])
        if not res:
            return ()
        date = res.group(1)
        # Convert this to epoch
        date = datetime.datetime.strptime(date.strip(), "%b %d %H:%M:%S")
        date = date.replace(year=datetime.datetime.now().year)
        date = date.timestamp()
        src = res.group(2)
        # Check if the log is a blacklist
        reg_result = r"(.*)dnsmasq\[.*\]: /etc/pihole/(gravity|black).list (.*) is 0.0.0.0"
        res = re.search(reg_result, log[1])
        if not res:
            return ()
        lst = res.group(2)
        domain = res.group(3)
        # once we have all this data, convert it into a massive tuple for log_event
        # sec, usec, src_ip, src_port, dst_ip, dst_port, proto, trail_type, trail, info, reference
        event_tuple = (date, 0, src, 9999, PIHOLE_IP, 53, "UDP", "DNS", domain, "Gravity Domain", "pi.hole")
        return event_tuple

class _ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass



def init():
    """
    Performs sensor initialization
    """

    global _multiprocessing

    read_config(CONFIG_FILE)

    try:
        import multiprocessing

        if config.PROCESS_COUNT > 1:
            _multiprocessing = multiprocessing
    except (ImportError, OSError, NotImplementedError):
        pass

def main():
    init()
    global PIHOLE_IP
    PIHOLE_IP = os.environ.get("PIHOLE_IP", "0.0.0.0")
    host = os.environ.get("DNSMASQ_LOGS_HOST", "0.0.0.0")
    try:
        port = os.environ.get("DNSMASQ_LOGS_PORT", "5151")
        port = int(port)
    except ValueError:
        port = 5151

    print("[*] Starting PiHole Log Processor on {}:{}".format(host, port))

    server = _ThreadedServer((host, port), LogServer)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    server.serve_forever()

if __name__ == '__main__':
    main()