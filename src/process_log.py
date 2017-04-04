#!/usr/bin/env python

import os, sys
import io
import re
import time
from dateutil import parser
import logging
import operator
import argparse

logging.basicConfig(level=logging.WARN, format="[%(name)s] %(levelname)s: %(message)s")
log_exec = logging.getLogger(os.path.basename(__file__))

class Request:
    """
    containins the parsed elements of the input log file
    """
    def __init__(self, line):
        """
        Accepts a log string and returns a structured format. Expects:
        host - - [timestamp] "method resource protocol" reply_code reply_bytes

        self.host: hostname
        self.timestamp: raw timestamp
        self.timeobj: timestamp in python's datetime format
        self.method: request method (GET, POST, etc.)
        self.resource: resource requested (file in /var/www or similar)
        self.protocol: HTTP protocol used
        self.reply_code: HTTP code of server's reply
        self.reply_bytes: reply size in bytes
        """
        self.host = re.split(' - - ', line)[0]

        # stores the raw timestamp, and a python datetime object
        self.timestamp = re.search(r'\[(.*?)\]', line).group(1)
        formatted_date = self.timestamp.replace('/', ' ').replace(':', ' ', 1)
        self.timeobj = parser.parse(formatted_date)

        # seperately stores method used, resource requested, and protocol used
        try:
            request = re.search(r'\"(.*?)\"', line).group(1)
        except:
            log_exec.debug('malformed request field in {}'.format(line))
            request = None
        try:
            self.method = request.split(' ')[0]  # GET, POST, etc.
        except:
            log_exec.debug('malformed HTTP method entry in {}'.format(line))
            self.method = None
        try:
            self.resource = request.split(' ')[1] # file in WEBROOT
        except:
            log_exec.debug('malformed resource request in {}'.format(line))
            self.resource = None
        try:
            self.protocol = request.split(' ')[2] # 1.0, 1.1, etc
        except:
            log_exec.debug('malformed protocol entry in {}'.format(line))
            self.protocol = None

        # stores server's reponse
        self.reply_code = int(line.split(' ')[-2])
        self.reply_bytes = line.split(' ')[-1]
        if self.reply_bytes == '-':
            self.reply_bytes = 0 # '-' is unknown and treated as 0
        else:
            self.reply_bytes = int(self.reply_bytes)


class Counter:
    """
    Feature 1+2: uses a dictionary to keep track of some item (ip address,
    resource) paired with some value (number of visits, bandwidth used)

    self.update(key, value) adds the key to self.counts dict, adding the value
    self.write(filename, n) writes n entries in self.counts dict to filename,
    sorted by value.
    """
    def __init__(self, name, filename):
        self.counts = {}

        # adds a simple logger
        self.log = logging.getLogger(name)
        self.log_hdl = logging.FileHandler(filename)
        self.log_hdl.setFormatter(logging.Formatter('%(message)s'))
        self.log.addHandler(self.log_hdl)
        self.log.setLevel(logging.INFO)

    def update(self, key, n):
        """adds count n to the provided key"""
        try:
            self.counts[key] += n
        except KeyError:
            self.counts[key] = n

    def logger(self, n=10, write_vals=True):
        """
        writes the top n lines of the sorted dictionary self.counts. if
        write_vals == True, writes out key,value pairs, otherwise, prints only
        the sorted keys.
        """
        if n > len(self.counts):
            log_exec.debug('number of hosts requested too large, printing all unique host counts')
            n = len(self.counts)
        if n <= 0:
            log_exec.debug('less than one host requested, printing top host count')
            n = 1

        # sort keys by value
        outputs = sorted(self.counts.items(), key=operator.itemgetter(1), reverse=True)
        outputs = outputs[:n]

        for output in outputs:
            if write_vals:
                self.log.info('{},{}'.format(output[0], output[1]))
            else:
                self.log.info('{}'.format(output[0]))


class Guardian():
    """
    Feature 4: for each host, uses python datetime objects to enforce access
    rules:
        1. No more than 3 login attempts every 20 seconds.
        2. If this threshold is breached, block the IP for 5 minutes.
    self.update_attepmts(host, timeobj):
    self.update_block(host, timeobj):
    self.logger(host, line):
    self.write(filename): batch writes self.log to filename to reduce disk I/O.
    """
    def __init__(self, name, filename):
        """
        self.attempts: dict of the times of the previous 3 failed logins/host.
        self.blocked:  dict of blocked hosts and time that they were blocked.
        self.log: a list of all requests by blocked hosts.
        """
        self.attempts = {}
        self.blocked = {}

        # adds a simple logger
        self.log = logging.getLogger(name)
        self.log_hdl = logging.FileHandler(filename)
        self.log_hdl.setFormatter(logging.Formatter('%(message)s'))
        self.log.addHandler(self.log_hdl)
        self.log.setLevel(logging.INFO)

    def update_attempts(self, host, timeobj):
        try:
            self.attempts[host].append(timeobj)
        except KeyError:
            self.attempts[host] = [timeobj]

        # keep the last three access attempts
        if len(self.attempts[host]) > 3:
            self.attempts[host] = self.attempts[host][1:]

        # host is an offender if last 3 attempts happened in under 20 sec
        if len(self.attempts[host]) == 3:
            log_exec.debug('calculating delta b/t {} and {}'.format(self.attempts[host][0], self.attempts[host][2]))
            delta = calc_delta_time(self.attempts[host][0], self.attempts[host][2])
            if delta <= 20:
                log_exec.info('host {} blocked for 5 minutes starting at {}'.format(
                    host, timeobj.strftime("%d.%b %Y %H:%M:%S")))
                self.blocked[host] = timeobj

    def update_block(self, host, timeobj):
        """if host is blocked and the time delta is over 5 mins, remove block"""
        try:
            blocked_time = self.blocked[host]
        except KeyError:
            return

        delta = calc_delta_time(blocked_time, timeobj)
        if delta >= 300:
            self.blocked.pop(host) # 60sec*5min=300, delete host from blocked

    def logger(self, host, line):
        """if host is blocked, log all access attempts"""
        try:
            blocked_time = self.blocked[host]
        except KeyError:
            return
        self.log.info(line)


def calc_delta_time(t1, t2):
    """returns difference in seconds between the datetime objects t2 and t1"""
    delta = t2 - t1
    delta = delta.days * 86400 + delta.seconds # 60sec*60mins*24hrs = 86400sec
    return(delta)


def main(log, logdir):
    """
    Opens log as a streaming text object, and passes each line to the parser.
    Parsed data is passed to the access dictionary, which keeps track of log
    attempts, with keys denoting addresses, and values being a tuple containing
    the first access attempt timestamp (in the last 20 second window) and the
    number of attempts since then. If the difference between the first access
    attempt and the current attempt is greater than 20 seconds, this is reset.
    """
    visit_count = Counter('visits per host', os.path.join(logdir, 'hosts.txt'))
    resource_bandwidth = Counter('bandwidth used', os.path.join(logdir, 'resources.txt'))
    login_guardian = Guardian('request denied', os.path.join(logdir, 'blocked.txt'))
    up_to_date = False # when true, does not attempt to write to logs

    try:
        fid = io.open(log, 'rb')
    except IOError:
        log_exec.error('logfile to monitor {} does not exist or is not readable'.format(log))
        sys.exit(1)

    # run as a daemon
    while True:

        fid_loc = fid.tell()
        line = fid.readline()

        if line:
            # parse the line into a Request object
            line = line.strip() # remove newline and other suprises
            data = Request(line.strip())
            log_exec.debug('parsed {}: host={}, timestamp={}, method={}, resource={}, protocol={}, reply code={}, reply size (bytes)={}'.format(
                line, data.host, data.timestamp, data.method, data.resource, data.protocol, data.reply_code, data.reply_bytes))

            # feature 1: visit count by host
            visit_count.update(data.host, 1)

            # feature 2: bandwidth use by resource
            if data.resource and data.reply_bytes:
                resource_bandwidth.update(data.resource, data.reply_bytes)

            # feature 4: login monitoring
            if data.resource == '/login':
                # check if this host is currently blocked, remove expired blocks
                login_guardian.update_block(data.host, data.timeobj)
                if data.reply_code == 401:
                    # check last 3 attempts from this host, block if required
                    login_guardian.update_attempts(data.host, data.timeobj)
            login_guardian.logger(data.host, line)

            up_to_date = False
        else:
            # no more lines in log. write summary stats and wait 10 ms
            if not up_to_date:
                visit_count.logger(n=10, write_vals=True)
                resource_bandwidth.logger(n=float('inf'), write_vals=False)
                up_to_date = True
            else:
                log_exec.info('awaiting changes in log')

            time.sleep(10/1000.0)
            fid.seek(fid_loc)

if __name__ == '__main__':

    log_exec.info('starting')
    argparser = argparse.ArgumentParser()
    argparser.add_argument("log", help="log file of web traffic to monitor")
    argparser.add_argument("logdir", help="output directory for logs")
    argparser.add_argument("-v", "--verbose", action="count",
        help="increase output verbosity")
    args = argparser.parse_args()

    if args.verbose > 1:
        log_exec.setLevel(logging.DEBUG)
    elif args.verbose == 1:
        log_exec.setLevel(logging.INFO)
    else:
        log_exec.setLevel(logging.WARN)

    main(args.log, args.logdir)


