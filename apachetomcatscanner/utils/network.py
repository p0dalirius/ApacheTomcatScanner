#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : network.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 Jan 2023

import socket

import requests
# Disable warnings of insecure connection for invalid certificates
requests.packages.urllib3.disable_warnings()
# Allow use of deprecated and weak cipher methods
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
try:
    requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
except AttributeError:
    pass


def is_target_a_windows_machine(target) -> bool:
    # if port 135 and 445 open
    if is_port_open(target, 135) and is_port_open(target, 445):
        return True
    else:
        return False


def is_target_a_windows_domain_controller(target) -> bool:
    # if port 135 and 445 and 88 open
    if is_target_a_windows_machine(target) and is_port_open(target, 88):
        return True
    else:
        return False


def is_port_open(target, port) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex((target, port)) == 0


def is_http_accessible(target, port, config, scheme="http"):
    url = "%s://%s:%d/" % (scheme, target, port)
    try:
        r = requests.get(
            url,
            timeout=config.request_timeout,
            proxies=config.request_proxies,
            verify=(not (config.request_no_check_certificate))
        )
        return True
    except Exception as e:
        config.debug("Error in is_http_accessible('%s', %d, '%s'): %s " % (target, port, scheme, e))
        return False