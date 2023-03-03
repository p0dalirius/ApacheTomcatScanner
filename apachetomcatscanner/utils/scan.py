#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : scan.py
# Author             : Podalirius (@podalirius_)
# Date created       : 29 Jul 2022

import base64
import datetime
import time
import traceback
import re
from apachetomcatscanner.utils.network import is_port_open, is_http_accessible
import requests
# Disable warnings of insecure connection for invalid certificates
requests.packages.urllib3.disable_warnings()
# Allow use of deprecated and weak cipher methods
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
try:
    requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
except AttributeError:
    pass


def is_tomcat_manager_accessible(target, port, path, config, scheme="http"):
    url = "%s://%s:%d%s" % (scheme, target, port, path)
    try:
        r = requests.get(
            url,
            timeout=config.request_timeout,
            proxies=config.request_proxies,
            verify=(not (config.request_no_check_certificate))
        )
        if r.status_code in [401]:
            return True
        else:
            return False
    except Exception as e:
        config.debug("Error in is_tomcat_manager_accessible('%s', %d, '%s'): %s " % (target, port, scheme, e))
        return False


def get_version_from_malformed_http_request(target, port, config, scheme="http"):
    url = "%s://%s:%d/{}" % (scheme, target, port)
    try:
        r = requests.get(
            url,
            timeout=config.request_timeout,
            proxies=config.request_proxies,
            verify=(not (config.request_no_check_certificate))
        )
    except Exception as e:
        config.debug("Error in get_version_from_malformed_http_request('%s', %d, '%s'): %s " % (target, port, scheme, e))
        return None
    if r.status_code in [400, 404, 500]:
        # Bug triggered
        matched = re.search(b"(<h3>)Apache Tomcat(/)?([^<]+)(</h3>)", r.content)
        if matched is not None:
            _, _, version, _ = matched.groups()
            version = version.decode('utf-8')
            return version


def try_default_credentials(target, port, path, config, scheme="http"):
    found_credentials = []
    url = "%s://%s:%d%s" % (scheme, target, port, path)
    try:
        for credentials in config.credentials:
            auth_string = bytes(credentials["username"] + ':' + credentials["password"], 'utf-8')
            r = requests.post(
                url,
                headers={
                    "Authorization": "Basic " + base64.b64encode(auth_string).decode('utf-8')
                },
                timeout=config.request_timeout,
                proxies=config.request_proxies,
                verify=(not (config.request_no_check_certificate))
            )
            if r.status_code in [200, 403]:
                found_credentials.append((r.status_code, credentials))
        return found_credentials
    except Exception as e:
        config.debug("Error in get_version_from_malformed_http_request('%s', %d, '%s'): %s " % (target, port, scheme, e))
        return found_credentials


def scan_worker(target, port, reporter, config, monitor_data):
    manager_access_paths = [
        "/manager/html",
        "/..;/manager/html"
    ]

    try:
        result = {"target": target}

        if is_port_open(target, port):
            for scheme in config.get_request_available_schemes():
                if is_http_accessible(target, port, config, scheme):
                    result["scheme"] = scheme
                    result["version"] = get_version_from_malformed_http_request(target, port, config, scheme)
                    if result["version"] is not None:
                        config.debug("Found version %s" % result["version"])

                        result["manager_accessible"] = False
                        result["manager_path"] = ""
                        for urlpath in manager_access_paths:
                            if is_tomcat_manager_accessible(target, port, urlpath, config, scheme):
                                result["manager_accessible"] = True
                                result["manager_path"] = urlpath
                                result["manager_url"] = "%s://%s:%d%s" % (scheme, target, port, urlpath)
                                break

                        credentials_found = []
                        if result["manager_accessible"]:
                            config.debug("Manager is accessible")
                            # Test for default credentials
                            credentials_found = try_default_credentials(target, port, result["manager_path"], config, scheme)

                        reporter.report_result(target, port, result, credentials_found)

        monitor_data["lock"].acquire()
        monitor_data["actions_performed"] = monitor_data["actions_performed"] + 1

        monitor_data["lock"].release()

    except Exception as e:
        if config.debug_mode:
            print("[Error in %s] %s" % (__name__, e))
            traceback.print_exc()


def monitor_thread(reporter, config, monitor_data):
    time.sleep(1)
    last_check, monitoring = 0, True
    while monitoring:
        new_check = monitor_data["actions_performed"]
        rate = (new_check - last_check)
        if not config.debug_mode:
            print("\r", end="")
        reporter.print_new_results()
        print("[%s] Status (%d/%d) %5.2f %% | Rate %d tests/s        " % (
                datetime.datetime.now().strftime("%Y/%m/%d %Hh%Mm%Ss"),
                new_check, monitor_data["total"], (new_check/monitor_data["total"])*100,
                rate
            ),
            end=("" if not config.debug_mode else "\n")
        )
        last_check = new_check
        time.sleep(1)
        if rate == 0 and monitor_data["actions_performed"] == monitor_data["total"]:
            monitoring = False

    if len(reporter._new_results) != 0:
        reporter.print_new_results()

    print()

