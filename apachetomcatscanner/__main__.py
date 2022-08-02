#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : __main__.py
# Author             : Podalirius (@podalirius_)
# Date created       : 24 Jul 2022

import argparse
import os
import sys

from apachetomcatscanner.Reporter import Reporter
from apachetomcatscanner.Config import Config
from apachetomcatscanner.VulnerabilitiesDB import VulnerabilitiesDB
from apachetomcatscanner.utils.scan import scan_worker
from sectools.windows.ldap import get_computers_from_domain
from sectools.network.domains import is_fqdn
from sectools.network.ip import is_ipv4_cidr, is_ipv4_addr, is_ipv6_addr, expand_cidr, expand_port_range
from concurrent.futures import ThreadPoolExecutor


VERSION = "2.2"

banner = """Apache Tomcat Scanner v%s - by @podalirius_\n""" % VERSION


def load_targets(options, config):
    targets = []

    # Loading targets from domain computers
    if options.auth_domain is not None and options.auth_user is not None and (options.auth_password is not None or options.auth_hash is not None):
        if options.verbose:
            print("[debug] Loading targets from computers in the domain '%s'" % options.auth_domain)
        targets = get_computers_from_domain(
            auth_domain=options.auth_domain,
            auth_dc_ip=options.auth_dc_ip,
            auth_username=options.auth_user,
            auth_password=options.auth_password,
            auth_hashes=options.auth_hash
        )

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
        elif is_fqdn(target):
            final_targets.append(target)

    final_targets = sorted(list(set(final_targets)))
    return final_targets


def load_ports(options, config):
    ports = []
    if "," in options.target_ports:
        for port in options.target_ports.split(','):
            ports += expand_port_range(port.strip())
    else:
        ports = expand_port_range(options.target_ports.strip())
    ports = sorted(list(set(ports)))
    return ports


def parseArgs():
    print(banner)
    parser = argparse.ArgumentParser(description="A python script to scan for Apache Tomcat server vulnerabilities.")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help='Verbose mode. (default: False)')
    parser.add_argument("--debug", default=False, action="store_true", help='Debug mode, for huge verbosity. (default: False)')
    parser.add_argument("-C", "--list-cves", default=False, action="store_true", help='List CVE ids affecting each version found. (default: False)')
    parser.add_argument("-T", "--threads", default=8, type=int, help='Number of threads (default: 5)')

    parser.add_argument("--xlsx", default=None, type=str, help='Export results to XLSX')
    parser.add_argument("--json", default=None, type=str, help='Export results to JSON')

    group_configuration = parser.add_argument_group()
    group_configuration.add_argument("-PI", "--proxy-ip", default=None, type=str, help='Proxy IP.')
    group_configuration.add_argument("-PP", "--proxy-port", default=None, type=int, help='Proxy port')
    group_configuration.add_argument("-rt", "--request-timeout", default=1, type=int, help='')

    group_targets_source = parser.add_argument_group()
    group_targets_source.add_argument("-tf", "--targets-file", default=None, type=str, help='Path to file containing a line by line list of targets.')
    group_targets_source.add_argument("-tt", "--target", default=[], type=str, action='append', help='Target IP, FQDN or CIDR')
    group_targets_source.add_argument("-tp", "--target-ports", default="8080", type=str, help='Target ports to scan top search for Apache Tomcat servers.')
    group_targets_source.add_argument("-ad", "--auth-domain", default=None, type=str, help='Windows domain to authenticate to.')
    group_targets_source.add_argument("-ai", "--auth-dc-ip", default=None, type=str, help='IP of the domain controller.')
    group_targets_source.add_argument("-au", "--auth-user", default=None, type=str, help='Username of the domain account.')
    group_targets_source.add_argument("-ap", "--auth-password", default=None, type=str, help='Password of the domain account.')
    group_targets_source.add_argument("-ah", "--auth-hash", default=None, type=str, help='LM:NT hashes to pass the hash for this user.')

    args = parser.parse_args()

    if (args.targets_file is None) and (len(args.target) == 0) and (args.auth_domain is None and args.auth_user is None and (args.auth_password is None or args.auth_hash is None)):
        parser.print_help()
        print("\n[!] No targets specified.")
        sys.exit(0)

    if args.auth_password is not None and args.auth_hash is not None:
        parser.print_help()
        print("\n[!] Options --auth-password/--auth-hash are mutually exclusive.")
        sys.exit(0)

    return args


def main():
    options = parseArgs()

    config = Config()
    config.set_debug_mode(options.debug)
    config.set_request_timeout(options.request_timeout)
    config.set_request_proxies(options.proxy_ip, options.proxy_port)
    config.set_list_cves_mode(options.list_cves)

    reporter = Reporter(config=config)

    vulns_db = VulnerabilitiesDB(config=config)

    # Parsing targets and ports
    targets = load_targets(options, config)
    ports = load_ports(options, config)
    if options.proxy_ip is not None and options.proxy_port is not None:
        print("[+] Targeting %d ports on %d targets through proxy %s:%d" % (len(ports), len(targets), options.proxy_ip, options.proxy_port))
    else:
        print("[+] Targeting %d ports on %d targets" % (len(ports), len(targets)))

    # Exploring targets
    if len(targets) != 0 and options.threads != 0:
        print("[+] Searching for Apache Tomcats servers on specified targets ...")
        with ThreadPoolExecutor(max_workers=min(options.threads, len(targets))) as tp:
            for target in targets:
                for port in ports:
                    tp.submit(scan_worker, target, port, reporter, vulns_db, config)
        print("[+] All done!")

    if options.xlsx is not None:
        reporter.export_xlsx(options.xlsx)
    if options.json is not None:
        reporter.export_json(options.json)


if __name__ == '__main__':
    main()
