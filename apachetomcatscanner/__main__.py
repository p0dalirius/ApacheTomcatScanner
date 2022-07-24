#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : __main__.py
# Author             : Podalirius (@podalirius_)
# Date created       : 24 Jul 2022


import argparse
import os
from apachetomcatscanner.utils import parse_ip_dns_cidr_target


VERSION = "1.0"

banner = """Apache Tomcat Scanner v%s - by @podalirius_\n""" % VERSION


def load_targets(options):
    targets = []

    # Loading targets from domain computers
    if options.auth_domain is not None and options.auth_user is not None and (options.auth_password is not None or options.auth_hash is not None):
        if options.verbose:
            print("[debug] Loading targets from computers in the domain '%s'" % options.auth_domain)

    # Loading targets line by line from a targets file
    if options.targets_file is not None:
        if os.path.exists(options.targets_file):
            if options.verbose:
                print("[debug] Loading targets line by line from targets file '%s'" % options.targets_file)
            f = open(options.targets_file, "r")
            for line in f.readlines():
                targets.append(line.strip())
            f.close()
        else:
            print("[!] Could not open targets file '%s'" % options.targets_file)

    # Loading targets from --target option
    if len(options.target) != 0:
        if options.verbose:
            print("[debug] Loading targets from --target options")
        for target in options.target:
            targets.append(target)

    # Sort uniq on targets list
    targets = sorted(list(set(targets)))

    # Parsing target to filter IP/DNS/CIDR
    # TODO

    return targets


def parseArgs():
    print(banner)
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
    if options.verbose:
        print("[debug] Loaded %d targets" % len(targets))

    # Exploring targets
    for target in targets:
        print(" - %s" % target)


if __name__ == '__main__':
    main()
