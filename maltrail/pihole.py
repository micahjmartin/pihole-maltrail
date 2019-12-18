import socketserver
import socket
import threading
import os
import datetime
import time
import re
import sys


from core.log import log_event, create_log_directory

from core.settings import config
from core.settings import CONFIG_FILE
from core.settings import read_config

# Tell malshare the source of the log

FORMAT_NAME="PiHole"
PIHOLE_IP=""
# 

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
    event_tuple = (date, 0, src, 9999, PIHOLE_IP, 53, "UDP", "DNS", domain, "PiHole Sink (spammer)", "pi.hole")
    return event_tuple

class FileReader(object):
    """Check if a file has changed, if so, process the logs from there"""
    def __init__(self, logfile):
        self.logfile = logfile
        self.last_checked = 0
    
    def loop(self, sleep=10):
        while True:
            # Check if the file has updated
            tim = os.stat(self.logfile)[8]
            if tim > self.last_checked:
                self.process_logfile()
            time.sleep(2)


    def process_logfile(self):
        # We need to read the file cause its new
        with open(self.logfile, "r+") as fil:
            data = fil.read().split()
            # Clear the file
            fil.write("")
            self.last_checked = time.time() + 1
        print("Ok we read the file at", self.last_checked)
        i = 0
        while True:
            # Weve processed all the logs like a good lumberjack
            if i >= len(data):
                return
            line = data[i]
            i += 1
            if "query[" in line and i < len(data):
                # Read the next line too
                line += "\n" + data[i]
                event_tuple = parse_log(line)
                if event_tuple:
                    print("[*] PiHole blocked '{}' for {}".format(event_tuple[8], event_tuple[2]))
                    log_event(event_tuple)


class LogServer(socketserver.BaseRequestHandler):
    def handle(self):
        while self.request:
            try:
                data = self.readline()
                if b"query[" in data:
                    # Read the next line too
                    data += self.readline()
                    data = data.decode("utf-8")
                    event_tuple = parse_log(data)
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
    
    

class _ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass



def init():
    """
    Performs sensor initialization
    """

    global _multiprocessing

    read_config(CONFIG_FILE)
    create_log_directory()

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
    
    pilog = os.environ.get("PIHOLE_LOG", False)
    if pilog:
        run_watcher(pilog)
    else:
        run_server()

def run_watcher(filename):
    fr = FileReader(filename)
    print("[*] Starting PiHole Log Processor to watch {}".format(filename))
    fr.loop()

def run_server():
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