#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Config.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2022

import json
import os


class Config(object):
    """
    Documentation for class Config
    """

    request_timeout = 5
    request_proxies = {}
    request_no_check_certificate = True
    request_http_headers = {}
    request_available_schemes = ["http"]

    list_cves_mode = False
    show_cves_descriptions_mode = False

    debug_mode = False
    verbose_mode = False

    no_colors = False

    credentials = {}

    def __init__(self):
        super(Config, self).__init__()
        self.__load_default_credentials()

    def debug(self, msg):
        if self.debug_mode:
            print("[debug]", msg)

    def __load_default_credentials(self):
        self.credentials = {}
        path_to_creds = os.path.dirname(__file__) + os.path.sep + 'data' + os.path.sep + 'credentials.json'
        f = open(path_to_creds, 'r')
        self.credentials = json.loads(f.read())["credentials"]
        f.close()
        return None

    def load_credentials_from_options(self, username, password, usernames_file, passwords_file):
        usernames = []
        passwords = []

        if username is not None:
            usernames.append(username)
        if usernames_file is not None:
            f = open(usernames_file, "r")
            for line in f.readlines():
                usernames.append(line.strip())
            f.close()

        if password is not None:
            passwords.append(password)
        if passwords_file is not None:
            f = open(passwords_file, "r")
            for line in f.readlines():
                passwords.append(line.strip())
            f.close()

        if len(usernames) != 0 and len(passwords) != 0:
            self.credentials = []
            for username in usernames:
                for password in passwords:
                    self.credentials.append({
                        "username": username,
                        "password": password,
                        "description": ""
                    })
        return len(self.credentials)

    # Get / Set functions

    def set_request_http_headers(self, http_headers):
        self.request_http_headers.clear()
        for header in http_headers:
            if ":" in header:
                key, value = header.split(":", 1)
                self.request_http_headers[key] = value
            else:
                self.request_http_headers[header] = ""

    def get_request_available_schemes(self):
        return self.request_available_schemes

    def set_request_available_schemes(self, only_http, only_https):
        self.request_available_schemes = []
        if only_https:
            self.request_available_schemes.append("https")
        elif only_http:
            self.request_available_schemes.append("http")
        else:
            self.request_available_schemes.append("http")
            self.request_available_schemes.append("https")

    def get_request_timeout(self):
        return self.request_timeout

    def set_request_timeout(self, value):
        self.request_timeout = value

    def get_request_no_check_certificate(self):
        return self.request_no_check_certificate

    def set_request_no_check_certificate(self, value):
        self.request_no_check_certificate = value

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
                    "http": "%s:%d" % (proxy_ip, proxy_port),
                    "https": "%s:%d" % (proxy_ip, proxy_port)
                }
            else:
                self.request_proxies[protocol] = "%s://%s:%d/" % (protocol, proxy_ip, proxy_port)
        return self.request_proxies

    def clear_request_proxies(self):
        self.request_proxies = {}

    def get_no_colors(self):
        return self.no_colors
    
    def set_no_colors(self, value):
        self.no_colors = value

    def get_show_cves_descriptions_mode(self):
        return self.show_cves_descriptions_mode

    def set_show_cves_descriptions_mode(self, value):
        self.show_cves_descriptions_mode = value
