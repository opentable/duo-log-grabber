#!/usr/bin/python
from __future__ import absolute_import
from __future__ import print_function
import six.moves.configparser
import optparse
import os
import sys
import time
import json
import socket

import duo_client

# For proxy support
from urllib.parse import urlparse


class BaseLog(object):

    def __init__(self, admin_api, path, logname, siem_server):
        self.admin_api = admin_api
        self.siem_server = siem_server
        self.path = path
        self.logname = logname

        self.mintime = (int(time.time()) - 1000000)
        self.events = []

    def get_events(self):
        raise NotImplementedError

    def print_events(self):
        raise NotImplementedError

    def get_last_timestamp_path(self):
        """
        Returns the path to the file containing the timestamp of the last
        event fetched.
        """
        filename = self.logname + "_last_timestamp_" + self.admin_api.host
        path = os.path.join(self.path, filename)
        return path

    def get_mintime(self):
        """
            Updates self.mintime which is the minimum timestamp of
            log events we want to fetch.
            self.mintime is > all event timestamps we have already fetched.
        """
        try:
            # Only fetch events that come after timestamp of last event
            path = self.get_last_timestamp_path()
            self.mintime = int(open(path).read().strip()) + 1
        except IOError:
            pass

    def write_last_timestamp(self):
        """
            Store last_timestamp so that we don't fetch the same events again
        """
        if self.logname == 'authentication':
            if not self.events['authlogs']:
                # Do not update last_timestamp
                return
        else:
            if not self.events:
                # Do not update last_timestamp
                return

        last_timestamp = 0

        if self.logname == 'authentication':
            for event in self.events['authlogs']:
                last_timestamp = max(last_timestamp, event['timestamp'])
        else:
            for event in self.events:
                last_timestamp = max(last_timestamp, event['timestamp'])

        path = self.get_last_timestamp_path()
        f = open(path, "w")
        f.write(str(last_timestamp))
        f.close()

    def run(self):
        """
        Fetch new log events and print them.
        """
        self.events = []
        self.get_mintime()
        self.get_events()
        self.print_events()
        self.write_last_timestamp()


class AdministratorLog(BaseLog):
    def __init__(self, admin_api, path, siem_server):
        BaseLog.__init__(self, admin_api, path, "administrator", siem_server)

    def get_events(self):
        self.events = self.admin_api.get_administrator_log(
            mintime=self.mintime,
        )

    def print_events(self):
        """
        Send logs to SIEM server
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            for event in self.events:
                s.connect((self.siem_server['host'], int(self.siem_server['port'])))
                s.sendall(json.dumps(event).encode('utf-8'))
                s.close()
        except Exception as e:
            print(e)
        finally:
            s.close()


class AuthenticationLog(BaseLog):
    def __init__(self, admin_api, path, siem_server):
        BaseLog.__init__(self, admin_api, path, "authentication", siem_server)

    def get_events(self):
        self.events = self.admin_api.get_authentication_log(
            api_version=2,
            mintime=(self.mintime * 1000),
        )

    def print_events(self):
        """
        Send logs to SIEM server
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            for event in self.events['authlogs']:
                s.connect((self.siem_server['host'], int(self.siem_server['port'])))
                s.sendall(json.dumps(event).encode('utf-8'))
                s.close()
        except Exception as e:
            print(e)
        finally:
            s.close()


class TelephonyLog(BaseLog):
    def __init__(self, admin_api, path, siem_server):
        BaseLog.__init__(self, admin_api, path, "telephony",siem_server)

    def get_events(self):
        self.events = self.admin_api.get_telephony_log(
            mintime=self.mintime,
        )

    def print_events(self):
        """
        Send logs to SIEM server
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            for event in self.events:
                s.connect((self.siem_server['host'], int(self.siem_server['port'])))
                s.sendall(json.dumps(event).encode('utf-8'))
                s.close()
        except Exception as e:
            print(e)
        finally:
            s.close()



def admin_api_from_config(config_path):
    """
    Return a duo_client.Admin object created using the parameters
    stored in a config file.
    """
    config = six.moves.configparser.ConfigParser()
    config.read(config_path)
    config_d = dict(config.items('duo'))
    ca_certs = config_d.get("ca_certs", None)
    if ca_certs is None:
        ca_certs = config_d.get("ca", None)

    ret = duo_client.Admin(
        ikey=config_d['ikey'],
        skey=config_d['skey'],
        host=config_d['host'],
        ca_certs=ca_certs,
    )

    http_proxy = config_d.get("http_proxy", None)
    if http_proxy is not None:
        proxy_parsed = urlparse(http_proxy)
        proxy_host = proxy_parsed.hostname
        proxy_port = proxy_parsed.port
        ret.set_proxy(host = proxy_host, port = proxy_port)

    return ret


def siem_from_config(config_path):
    config = six.moves.configparser.ConfigParser()
    config.read(config_path)
    config_d = dict(config.items('siem'))

    return config_d

def main():
    parser = optparse.OptionParser(usage="%prog [<config file path>]")
    (options, args) = parser.parse_args(sys.argv[1:])

    if len(sys.argv) == 1:
        config_path = os.path.abspath(__file__)
        config_path = os.path.dirname(config_path)
        config_path = os.path.join(config_path, "duo.conf")
    else:
        config_path = os.path.abspath(sys.argv[1])

    admin_api = admin_api_from_config(config_path)
    siem_server = siem_from_config(config_path)

    # Use the directory of the config file to store the last event tstamps
    path = os.path.dirname(config_path)

    while True:
        for logclass in (AdministratorLog, AuthenticationLog, TelephonyLog):
            log = logclass(admin_api, path,siem_server)
            log.run()
        time.sleep(60)


if __name__ == '__main__':
    main()
