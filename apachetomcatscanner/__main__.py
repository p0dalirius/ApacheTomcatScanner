#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : __main__.py
# Author             : Podalirius (@podalirius_)
# Date created       : 24 Jul 2022

import argparse
import os
from apachetomcatscanner.utils.scan import scan_worker
from sectools.network.ip import is_ipv4_cidr, is_ipv4_addr, is_ipv6_addr, expand_cidr
from concurrent.futures import ThreadPoolExecutor


VERSION = "1.2"

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

    final_targets = []
    # Parsing target to filter IP/DNS/CIDR
    for target in targets:
        if is_ipv4_cidr(target):
            final_targets += expand_cidr(target)
        elif is_ipv4_addr(target):
            final_targets.append(target)
        elif is_ipv6_addr(target):
            final_targets.append(target)

    final_targets = sorted(list(set(final_targets)))
    return final_targets


def parseArgs():
    print(banner)
    parser = argparse.ArgumentParser(description="A python script to scan for Apache Tomcat server vulnerabilities.")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help='Verbose mode. (default: False)')
    parser.add_argument("-T", "--threads", default=8, type=int, help='Number of threads (default: 5)')

    group_configuration = parser.add_argument_group()
    group_configuration.add_argument("-PI", "--proxy-ip", default=None, help='')
    group_configuration.add_argument("-PP", "--proxy-port", default=None, help='')

    group_targets_source = parser.add_argument_group()
    group_targets_source.add_argument("-tf", "--targets-file", default=None, help='')
    group_targets_source.add_argument("-tt", "--target", default=[], action='append', help='Target IP, FQDN or CIDR')
    group_targets_source.add_argument("-tp", "--target-ports", default="8080", help='Target ports to scan top search for Apache Tomcat servers.')
    group_targets_source.add_argument("-ad", "--auth-domain", default=None, help='')
    group_targets_source.add_argument("-au", "--auth-user", default=None, help='')
    group_targets_source.add_argument("-ap", "--auth-password", default=None, help='')
    group_targets_source.add_argument("-ah", "--auth-hash", default=None, help='')

    args = parser.parse_args()

    if (args.targets_file is None) and (len(args.target) == 0) and (args.auth_domain is None and args.auth_user is None and (args.auth_password is None or args.auth_hash is None)):
        parser.print_help()
        print("\n[!] No targets specified.")

    if args.auth_password is not None and args.auth_hash is not None:
        parser.print_help()
        print("\n[!] Options --auth-password/--auth-hash are mutually exclusive.")

    return args


def main():
    options = parseArgs()

    # Parsing targets and ports
    targets = load_targets(options)
    if "," in options.target_ports:
        ports = [int(port.strip()) for port in options.target_ports.split(',')]
        print("[+] Targeting %d ports on %d targets" % (len(ports), len(targets)))
    else:
        ports = [int(options.target_ports.strip())]
        print("[+] Targeting %d port (%s) on %d targets" % (len(ports), ports[0], len(targets)))

    # Exploring targets
    print("[+] Searching for Apache Tomcats servers on specified targets ...")
    results = {}
    with ThreadPoolExecutor(max_workers=min(options.threads, len(targets))) as tp:
        for target in targets:
            for port in ports:
                tp.submit(scan_worker, target, port, results)
    print("[+] All done!")


if __name__ == '__main__':
    main()
