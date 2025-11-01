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
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ":HIGH:!DH:!aNULL"
try:
    requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += (
        ":HIGH:!DH:!aNULL"
    )
except AttributeError:
    pass


def is_target_a_windows_machine(target) -> bool:
    """
    Check if the target is a Windows machine.

    Args:
        target: The target to check.

    Returns:
        True if the target is a Windows machine, False otherwise.
    """
    # if port 135 and 445 open
    if is_port_open(target, 135) and is_port_open(target, 445):
        return True
    else:
        return False


def is_target_a_windows_domain_controller(target) -> bool:
    """
    Check if the target is a Windows domain controller.

    Args:
        target: The target to check.

    Returns:
        True if the target is a Windows domain controller, False otherwise.
    """
    # if port 135 and 445 and 88 open
    if is_target_a_windows_machine(target) and is_port_open(target, 88):
        return True
    else:
        return False


def is_port_open(target, port) -> bool:
    """
    Check if the port is open on the target.

    Args:
        target: The target to check.
        port: The port to check.

    Returns:
        True if the port is open on the target, False otherwise.

    Raises:
        Exception: If an error occurs while checking if the port is open on the target.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.1)
        # Non-existant domains cause a lot of errors, added error handling
        try:
            return s.connect_ex((target, port)) == 0
        except Exception:
            return False


def is_http_accessible(target, port, config, scheme="http"):
    """
    Check if the target is accessible via HTTP.

    Args:
        target: The target to check.
        port: The port to check.
        config: The config object.
        scheme: The scheme to use.

    Returns:
        True if the target is accessible via HTTP, False otherwise.

    Raises:
        Exception: If an error occurs while checking if the target is accessible via HTTP.
    """
    url = "%s://%s:%d/" % (scheme, target, port)
    try:
        r = requests.get(
            url,
            timeout=config.request_timeout,
            proxies=config.request_proxies,
            headers=config.request_http_headers,
            verify=(not (config.request_no_check_certificate)),
        )
        return True
    except Exception as e:
        config.debug(
            "Error in is_http_accessible('%s', %d, '%s'): %s "
            % (target, port, scheme, e)
        )
        return False
