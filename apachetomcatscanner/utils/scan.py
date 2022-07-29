#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : scan.py
# Author             : Podalirius (@podalirius_)
# Date created       : 29 Jul 2022

import base64
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


def try_default_credentials(target, port):
    found_credentials = []
    url = "http://%s:%d/manager/html" % (target, port)
    try:
        couple_username_passwords = [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "tomcat"},
            {"username": "tomcat", "password": "tomcat"},
            {"username": "tomcat", "password": "s3cret"}
        ]
        for credentials in couple_username_passwords:
            auth_string = bytes(credentials["username"] + ':' + credentials["password"], 'utf-8')
            r = requests.post(
                url,
                headers={
                    "Authorization": "Basic " + base64.b64encode(auth_string).decode('utf-8')
                }
            )
            if r.status_code in [200, 403]:
                found_credentials.append((r.status_code, credentials))
        return found_credentials
    except Exception as e:
        return found_credentials


def scan_worker(target, port, results, timeout=1):
    DEBUG = False
    if DEBUG: print("[debug] scan_worker('%s', %d)" % (target, port))
    result = {"target": target}
    if is_http_accessible(target, port):
        result["version"] = get_version_from_malformed_http_request(target, port)
        if DEBUG: print("[debug] Found version %s" % result["version"])

        result["manager_accessible"] = is_tomcat_manager_accessible(target, port)
        if DEBUG and result["manager_accessible"]: print("[debug] Manager is accessible")

        credentials = []
        if result["manager_accessible"]:
            # Test for default credentials
            credentials = try_default_credentials(target, port)

        str_found_creds = []
        if len(credentials) != 0:
            for statuscode, creds in credentials:
                str_found_creds.append("(username:\x1b[1;92m%s\x1b[0m password:\x1b[1;92m%s\x1b[0m)" % (creds["username"], creds["password"]))

        print("[>] [Apache Tomcat/\x1b[1;95m%s\x1b[0m] on \x1b[1;93m%s\x1b[0m:\x1b[1;93m%d\x1b[0m (manager:%s) %s" % (
                result["version"],
                target,
                port,
                ("\x1b[1;92maccessible\x1b[0m" if result["manager_accessible"] else "\x1b[1;91mnot accessible\x1b[0m"),
                ' '.join(str_found_creds)
            )
        )

