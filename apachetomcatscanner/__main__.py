#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : __main__.py
# Author             : Podalirius (@podalirius_)
# Date created       : 24 Jul 2022


import argparse
import os
from apachetomcatscanner.utils import parse_ip_dns_cidr_target


VERSION = "1.0"

banner = """Apache Tomcat Scanner v%s - by @podalirius_""" % VERSION


def load_targets(options):
    targets = []

    # Load targets from domain computers
    if options.auth_domain is not None and options.auth_user is not None and (options.auth_password is not None or options.auth_hash is not None):
        pass

    # Load targets line by line from a targets file
    if options.targets_file is not None:
        if os.path.exists(options.targets_file):
            f = open(options.targets_file, "r")
            for line in f.readlines():
                targets.append(line.strip())
            f.close()
        else:
            print("[!] Could not open targets file '%s'" % options.targets_file)

    # Load targets from --target option
    if len(options.target) != 0:
        for target in options.target:
            targets.append(target)

    # Sort uniq on targets list
    targets = sorted(list(set(targets)))
    return targets


def parseArgs():
    parser = argparse.ArgumentParser(description="Description message")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help='Verbose mode. (default: False)')

    group_configuration = parser.add_argument_group()
    group_configuration.add_argument("-PI", "--proxy-ip", default=None, help='')
    group_configuration.add_argument("-PP", "--proxy-port", default=None, help='')

    group_targets_source = parser.add_argument_group()
    group_targets_source.add_argument("-tf", "--targets-file", default=None, help='')
    group_targets_source.add_argument("-tt", "--target", default=[], action='append', help='Target IP, FQDN or CIDR')
    group_targets_source.add_argument("-ad", "--auth-domain", default=None, help='')
    group_targets_source.add_argument("-au", "--auth-user", default=None, help='')
    group_targets_source.add_argument("-ap", "--auth-password", default=None, help='')
    group_targets_source.add_argument("-ah", "--auth-hash", default=None, help='')

    args = parser.parse_args()

    if args.auth_password is not None and args.auth_hash is not None:
        print("[!] Options --auth-password/--auth-hash are mutually exclusive.")

    return args


def main():
    options = parseArgs()

    targets = load_targets(options)

    # Exploring targets
    for target in targets:
        print(" - %s" % target)


if __name__ == '__main__':
    main()
