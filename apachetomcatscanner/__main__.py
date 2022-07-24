#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : __main__.py
# Author             : Podalirius (@podalirius_)
# Date created       : 24 Jul 2022


import argparse
from apachetomcatscanner.utils import parse_ip_dns_cidr_target


VERSION = "1.0"

banner = """Apache Tomcat Scanner v%s - by @podalirius_""" % VERSION


def parseArgs():
    parser = argparse.ArgumentParser(description="Description message")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help='Verbose mode. (default: False)')
    parser.add_argument('targets', default=[], nargs="+", help='List of targets IP, FQDN or CIDR')
    return parser.parse_args()


def main():
    options = parseArgs()

    targets = ["127.0.0.1:10001"]
    # for target in options.targets:
    #     targets += parse_ip_dns_cidr_target(target)

    # Exploring targets
    for target in targets:
        pass
    

if __name__ == '__main__':
    main()
