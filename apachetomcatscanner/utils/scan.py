#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : scan.py
# Author             : Podalirius (@podalirius_)
# Date created       : 29 Jul 2022
import re

import requests


def is_target_a_windows_machine() -> bool:
    # if port 135 and 445 open
    pass


def is_target_a_windows_domain_controller() -> bool:
    # if port 135 and 445 and 88 and ldap/ldaps open
    pass


def is_http_accessible(target, port, timeout=1):
    url = "http://%s:%d/" % (target, port)
    try:
        r = requests.get(url, timeout=timeout)
        return True
    except Exception as e:
        return False


def is_tomcat_manager_accessible(target, port, path="/manager/html", timeout=1):
    url = "http://%s:%d%s" % (target, port, path)
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code in [200, 401]:
            return True
        else:
            return False
    except Exception as e:
        return False


def get_version_from_malformed_http_request(target, port):
    url = "http://%s:%d/{}" % (target, port)
    try:
        r = requests.get(url)
    except Exception as e:
        return None
    if r.status_code in [400, 404, 500]:
        # Bug triggered
        matched = re.search(b"(<h3>)Apache Tomcat(/)?([^<]+)(</h3>)", r.content)
        if matched is not None:
            _, _, version, _ = matched.groups()
            version = version.decode('utf-8')
            return version


def scan_worker(target, port, results, timeout=1):
    DEBUG = False
    if DEBUG: print("[debug] scan_worker('%s', %d)" % (target, port))
    result = {"target": target}
    if is_http_accessible(target, port):
        result["version"] = get_version_from_malformed_http_request(target, port)
        if DEBUG: print("[debug] Found version %s" % result["version"])

        result["manager_accessible"] = is_tomcat_manager_accessible(target, port)
        if DEBUG and result["manager_accessible"]: print("[debug] Manager is accessible")

        if result["manager_accessible"]:
            # Test for default credentials
            pass

        print("[>] [Apache Tomcat/\x1b[1;95m%s\x1b[0m] on \x1b[1;93m%s\x1b[0m:\x1b[1;93m%d\x1b[0m [Manager:%s]" % (
                result["version"],
                target,
                port,
                ("\x1b[1;92maccessible\x1b[0m" if result["manager_accessible"] else "\x1b[1;91mnot accessible\x1b[0m")
            )
        )
