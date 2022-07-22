#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : __main__.py
# Author             : Podalirius (@podalirius_)
# Date created       : 22 Jul 2022


import argparse
import os
import sys

from coercer.protocols.MS_EFSR import MS_EFSR
from coercer.protocols.MS_FSRVP import MS_FSRVP
from coercer.protocols.MS_DFSNM import MS_DFSNM
from coercer.protocols.MS_RPRN import MS_RPRN
from coercer.utils.smb import connect_to_pipe, can_bind_to_protocol, get_available_pipes_and_protocols


VERSION = "1.0"

banner = """Apache Tomcat Scanner v%s - by @podalirius_""" % VERSION


def parseArgs():
    parser = argparse.ArgumentParser(description="Description message")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help='Verbose mode. (default: False)')
    parser.add_argument('targets', default=[], nargs="+", help='List of targets IP, FQDN or CIDR')
    return parser.parse_args()


def main():
    targets = []
    for target in options.targets:
        targets += parse_ip_dns_cidr_target(target)


if __name__ == '__main__':
    main()
