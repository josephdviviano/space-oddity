#!/usr/bin/env python

import os, sys
import io
import re
import time
from dateutil import parser
import logging
import operator

logging.basicConfig(level=logging.WARN, format="[%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger(os.path.basename(__file__))

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
        request = re.search(r'\"(.*?)\"', line).group(1)
        self.method = request.split(' ')[0]   # GET, POST, etc.
        self.resource = request.split(' ')[1] # file in /var/www (or similar)
        try:
            self.protocol = request.split(' ')[2] # 1.0, 1.1, etc
        except:
            self.protocol = None # not always reported

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
    def __init__(self):
        self.counts = {}

    def update(self, key, n):
        """adds count n to the provided key"""
        try:
            self.counts[key] += n
        except KeyError:
            self.counts[key] = n

    def write(self, filename, n=10, write_vals=True):
        """
        writes the top n lines of the sorted dictionary self.counts. if
        write_vals == True, writes out key,value pairs, otherwise, prints only
        the sorted keys.
        """
        if n > len(self.counts):
            logger.debug('number of hosts requested too large, printing all unique host counts')
            n = len(self.counts)
        if n <= 0:
            logger.debug('less than one host requested, printing top host count')
            n = 1

        # sort keys by value
        outputs = sorted(self.counts.items(), key=operator.itemgetter(1), reverse=True)
        outputs = outputs[:n]

        with open(filename, 'wb') as fid:
            for output in outputs:
                if write_vals:
                    fid.write('{},{}\n'.format(output[0], output[1]))
                else:
                    fid.write('{}\n'.format(output[0]))


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
    def __init__(self):
        """
        self.attempts: dict of the times of the previous 3 failed logins/host.
        self.blocked:  dict of blocked hosts and time that they were blocked.
        self.log: a list of all requests by blocked hosts.
        """
        self.attempts = {}
        self.blocked = {}
        self.log = []

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
            logger.debug('calculating delta b/t {} and {}'.format(self.attempts[host][2], self.attempts[host][0]))
            delta = calc_delta_time(self.attempts[host][0], self.attempts[host][2])
            if delta <= 20:
                logger.info('host {} blocked for 5 minutes starting at {}'.format(
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
        self.log.append(line)

    def write(self, filename):
        """writes self.log to filename, and resets the log"""
        with open(filename, 'wb') as fid:
            for line in self.log:
                fid.write('{}\n'.format(line))


def calc_delta_time(t1, t2):
    """returns difference in seconds between the datetime objects t2 and t1"""
    delta = t2 - t1
    delta = delta.days * 86400 + delta.seconds # 60sec*60mins*24hrs = 86400sec
    return(delta)


def monitor_log(log, logdir):
    """
    Opens log as a streaming text object, and passes each line to the parser.
    Parsed data is passed to the access dictionary, which keeps track of log
    attempts, with keys denoting addresses, and values being a tuple containing
    the first access attempt timestamp (in the last 20 second window) and the
    number of attempts since then. If the difference between the first access
    attempt and the current attempt is greater than 20 seconds, this is reset.
    """
    visit_count = Counter()
    resource_bandwidth = Counter()
    login_guardian = Guardian()
    up_to_date = False # when true, does not attempt to write to logs

    try:
        fid = io.open(log, 'rb')
    except IOError:
        logger.error('logfile to monitor {} does not exist or is not readable'.format(log))
        sys.exit(1)

    # run as a daemon
    while True:
        fid_loc = fid.tell()
        line = fid.readline()

        if line:
            # parse the line into a Request object
            line = line.strip() # remove newline and other suprises
            data = Request(line.strip())
            logger.debug('parsed {}: host={}, timestamp={}, method={}, resource={}, protocol={}, reply code={}, reply size (bytes)={}'.format(
                line, data.host, data.timestamp, data.method, data.resource, data.protocol, data.reply_code, data.reply_bytes))

            # feature 1: visit count by host
            visit_count.update(data.host, 1)

            # feature 2: bandwidth use by resource
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
            # no more lines in log. write output and wait 10 ms
            if not up_to_date:
                visit_count.write(os.path.join(logdir, 'hosts.txt'),
                    n=10, write_vals=True)
                resource_bandwidth.write(os.path.join(logdir, 'resources.txt'),
                    n=float('inf'), write_vals=False)
                login_guardian.write(os.path.join(logdir, 'blocked.txt'))
                up_to_date = True
            else:
                logger.info('awaiting changes in log')

            time.sleep(10/1000.0)
            fid.seek(fid_loc)

if __name__ == '__main__':

    logger.info('starting')
    debug = True
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    monitor_log(sys.argv[1], sys.argv[2])


