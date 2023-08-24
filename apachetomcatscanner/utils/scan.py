#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : scan.py
# Author             : Podalirius (@podalirius_)
# Date created       : 29 Jul 2022

import base64
import datetime
import time
import traceback
import urllib.parse
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


def is_tomcat_manager_accessible(url_manager, config):
    try:
        r = requests.get(
            url_manager,
            timeout=config.request_timeout,
            proxies=config.request_proxies,
            verify=(not (config.request_no_check_certificate))
        )
        if r.status_code in [401]:
            return True
        else:
            return False
    except Exception as e:
        config.debug("Error in is_tomcat_manager_accessible('%s'): %s " % (url_manager, e))
        return False


def get_version_from_malformed_http_request(url, config):
    version = None
    url_depth = len(url.split('/')[3:])
    test_urls = [
        ("GET", url + "/{}"),
        ("GET", url + "/" + "..;/" * url_depth + "{}"),
        ("GET", url + "/..;/..;/"),
        ("ACL", url + "/"),
    ]
    test_urls = list(set(test_urls))
    try:
        for test_method, test_url in test_urls:
            if version is None:
                r = requests.request(
                    method=test_method,
                    url=test_url,
                    timeout=config.request_timeout,
                    proxies=config.request_proxies,
                    verify=(not (config.request_no_check_certificate))
                )
                if r.status_code in [400, 401, 403, 404, 405, 500]:
                    # Bug triggered
                    matched = re.search(b"(<h3>)Apache Tomcat(/)?([^<]+)(</h3>)", r.content)
                    if matched is not None:
                        _, _, _version, _ = matched.groups()
                        version = _version.decode('utf-8')
        # If version is still None, try to get it through the docs
        if version is None and True:
            r = requests.request(
                method="GET",
                url=(url + "/docs/"),
                timeout=config.request_timeout,
                proxies=config.request_proxies,
                verify=(not (config.request_no_check_certificate))
            )
            if r.status_code == 200:
                matched = re.search(b'(<div class="versionInfo">)Version( )*([^,]+),([^<]+)(</div>)', r.content)
                if matched is not None:
                    _, _, _version, _, _ = matched.groups()
                    version = _version.decode('utf-8')
                    print("Version using docs")
        return version
    except Exception as e:
        config.debug("Error in get_version_from_malformed_http_request('%s'): %s " % (url, e))
        return None


def try_default_credentials(url_manager, config):
    found_credentials = []
    try:
        for credentials in config.credentials:
            auth_string = bytes(credentials["username"] + ':' + credentials["password"], 'utf-8')
            r = requests.post(
                url_manager,
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
        config.debug("Error in get_version_from_malformed_http_request('%s'): %s " % (url_manager, e))
        return found_credentials


def process_url(scheme, target, port, url, config, reporter):
    url = url.rstrip('/')
    baseurl = '/'.join(url.split('/')[:3])
    url_depth = len(url.split('/')[3:])

    # Generating urls, with bypasses
    possible_manager_urls = [
        url,
        url + "/manager/html",
        url + "/..;/manager/html",
        baseurl + "/manager/html",
        baseurl + "/..;/manager/html",
        url + "/" + "..;/" * url_depth + "manager/html",
    ]
    possible_manager_urls = list(set(possible_manager_urls))

    result = {
        "target": target,
        "scheme": scheme,
        "version": get_version_from_malformed_http_request(url, config)
    }

    if result["version"] is not None:
        config.debug("Found version %s" % result["version"])

        result["manager_accessible"] = False
        result["manager_path"] = ""
        for url_manager in possible_manager_urls:
            if is_tomcat_manager_accessible(url_manager, config):
                result["manager_accessible"] = True
                result["manager_path"] = '/'.join(url_manager.split('/')[3:])
                result["manager_url"] = url_manager
                break

        # Testing credentials
        credentials_found = []
        if result["manager_accessible"]:
            config.debug("Manager is accessible")
            # Test for default credentials
            credentials_found = try_default_credentials(url_manager, config)

        reporter.report_result(target, port, result, credentials_found)

    return result


def scan_worker(target, port, reporter, config, monitor_data):
    try:
        if is_port_open(target, port):
            for scheme in config.get_request_available_schemes():
                if is_http_accessible(target, port, config, scheme):
                    url = "%s://%s:%d/" % (scheme, target, port)
                    process_url(scheme, target, port, url, config, reporter)

        monitor_data["lock"].acquire()
        monitor_data["actions_performed"] = monitor_data["actions_performed"] + 1
        monitor_data["lock"].release()

    except Exception as e:
        if config.debug_mode:
            print("[Error in %s] %s" % (__name__, e))
            traceback.print_exc()


def scan_worker_url(url, reporter, config, monitor_data):
    try:
        scheme = urllib.parse.urlparse(url).scheme
        netloc = urllib.parse.urlparse(url).netloc

        host, port = None, None
        matched = re.search("([^:]+)(:([0-9]+))?$", netloc)
        if matched is not None:
            host, _, port = matched.groups()
            if port is None:
                if scheme == "http":
                    port = 80
                elif scheme == "https":
                    port = 443
            else:
                port = int(port)

        if is_http_accessible(host, port, config, scheme):
            process_url(scheme, host, port, url, config, reporter)

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

