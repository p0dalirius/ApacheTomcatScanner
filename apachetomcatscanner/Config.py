#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Config.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2022


class Config(object):
    """
    Documentation for class Config
    """

    request_timeout = 1
    request_proxies = {}

    list_cves_mode = False

    debug_mode = False
    verbose_mode = False

    def __init__(self):
        super(Config, self).__init__()

    def debug(self, msg):
        if self.debug_mode:
            print("[debug]", msg)

    # Get / Set functions

    def get_request_timeout(self):
        return self.request_timeout

    def set_request_timeout(self, value):
        self.request_timeout = value

    def get_list_cves_mode(self):
        return self.list_cves_mode

    def set_list_cves_mode(self, value):
        self.list_cves_mode = value

    def get_debug_mode(self):
        return self.debug_mode

    def set_debug_mode(self, value):
        if value == True:
            self.verbose_mode = True
        self.debug_mode = value

    def get_verbose_mode(self):
        return self.verbose_mode

    def set_verbose_mode(self, value):
        self.verbose_mode = value

    def get_request_proxies(self):
        return self.request_proxies

    def set_request_proxies(self, proxy_ip, proxy_port, protocol=None):
        if proxy_ip is not None and proxy_port is not None:
            if protocol is None:
                self.request_proxies = {
                    "http": "http://%s:%d/" % (proxy_ip, proxy_port),
                    "https": "https://%s:%d/" % (proxy_ip, proxy_port)
                }
            else:
                self.request_proxies[protocol] = "%s://%s:%d/" % (protocol, proxy_ip, proxy_port)
        return self.request_proxies

    def clear_request_proxies(self):
        self.request_proxies = {}
