#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : __main__.py
# Author             : Podalirius (@podalirius_)
# Date created       : 24 Jul 2022
import threading

import argparse
import os
import sys

from apachetomcatscanner.Reporter import Reporter
from apachetomcatscanner.Config import Config
from apachetomcatscanner.VulnerabilitiesDB import VulnerabilitiesDB
from apachetomcatscanner.utils.scan import scan_worker, monitor_thread
from sectools.windows.ldap import get_computers_from_domain, get_servers_from_domain, get_subnets
from sectools.network.domains import is_fqdn
from sectools.network.ip import is_ipv4_cidr, is_ipv4_addr, is_ipv6_addr, expand_cidr, expand_port_range
from concurrent.futures import ThreadPoolExecutor


VERSION = "3.0"

banner = """Apache Tomcat Scanner v%s - by @podalirius_\n""" % VERSION


def load_targets(options, config):
    targets = []

    # Loading targets from domain computers
    if options.auth_dc_ip is not None and options.auth_user is not None and (options.auth_password is not None or options.auth_hashes is not None) and options.servers_only is False:
        if options.debug:
            print("[debug] Loading targets from computers in the domain '%s'" % options.auth_domain)
        targets += get_computers_from_domain(
            auth_domain=options.auth_domain,
            auth_dc_ip=options.auth_dc_ip,
            auth_username=options.auth_user,
            auth_password=options.auth_password,
            auth_hashes=options.auth_hashes,
            use_ldaps=options.ldaps,
            __print=True
        )

    # Loading targets from domain servers
    if options.auth_dc_ip is not None and options.auth_user is not None and (options.auth_password is not None or options.auth_hashes is not None) and options.servers_only is True:
        if options.debug:
            print("[debug] Loading targets from servers in the domain '%s'" % options.auth_domain)
        targets += get_servers_from_domain(
            auth_domain=options.auth_domain,
            auth_dc_ip=options.auth_dc_ip,
            auth_username=options.auth_user,
            auth_password=options.auth_password,
            auth_hashes=options.auth_hashes,
            use_ldaps=options.ldaps,
            __print=True
        )

    # Loading targets from subnetworks of the domain
    if options.auth_dc_ip is not None and options.auth_user is not None and (options.auth_password is not None or options.auth_hashes is not None):
        if options.debug:
            print("[debug] Loading targets from servers in the domain '%s'" % options.auth_domain)
        targets += get_subnets(
            auth_domain=options.auth_domain,
            auth_dc_ip=options.auth_dc_ip,
            auth_username=options.auth_user,
            auth_password=options.auth_password,
            auth_hashes=options.auth_hashes,
            use_ldaps=options.ldaps,
            __print=True
        )

    # Loading targets line by line from a targets file
    if options.targets_file is not None:
        if os.path.exists(options.targets_file):
            if options.debug:
                print("[debug] Loading targets line by line from targets file '%s'" % options.targets_file)
            f = open(options.targets_file, "r")
            for line in f.readlines():
                targets.append(line.strip())
            f.close()
        else:
            print("[!] Could not open targets file '%s'" % options.targets_file)

    # Loading targets from a single --target option
    if len(options.target) != 0:
        if options.debug:
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
        else:
            if options.debug:
                print("[debug] Target '%s' was not added." % target)

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
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode. (default: False)")
    parser.add_argument("--debug", default=False, action="store_true", help="Debug mode, for huge verbosity. (default: False)")
    parser.add_argument("-C", "--list-cves", default=False, action="store_true", help="List CVE ids affecting each version found. (default: False)")
    parser.add_argument("-T", "--threads", default=250, type=int, help="Number of threads (default: 250)")
    parser.add_argument("-s", "--servers-only", default=False, action="store_true", help="If querying ActiveDirectory, only get servers and not all computer objects. (default: False)")

    parser.add_argument("--only-http", default=False, action="store_true", help="Scan only with HTTP scheme. (default: False, scanning with both HTTP and HTTPs)")
    parser.add_argument("--only-https", default=False, action="store_true", help="Scan only with HTTPs scheme. (default: False, scanning with both HTTP and HTTPs)")
    # parser.add_argument("--no-check-certificate", default=False, action="store_true", help="Do not check certificate. (default: False)")

    group_export = parser.add_argument_group("Export results")
    group_export.add_argument("--export-xlsx", dest="export_xlsx", type=str, default=None, required=False, help="Output XLSX file to store the results in.")
    group_export.add_argument("--export-json", dest="export_json", type=str, default=None, required=False, help="Output JSON file to store the results in.")
    group_export.add_argument("--export-sqlite", dest="export_sqlite", type=str, default=None, required=False, help="Output SQLITE3 file to store the results in.")

    group_configuration = parser.add_argument_group("Advanced configuration")
    group_configuration.add_argument("-PI", "--proxy-ip", default=None, type=str, help="Proxy IP.")
    group_configuration.add_argument("-PP", "--proxy-port", default=None, type=int, help="Proxy port")
    group_configuration.add_argument("-rt", "--request-timeout", default=1, type=int, help="Set the timeout of HTTP requests.")
    group_configuration.add_argument("--tomcat-username", default=None, help="Set the timeout of HTTP requests.")
    group_configuration.add_argument("--tomcat-usernames-file", default=None, help="Set the timeout of HTTP requests.")
    group_configuration.add_argument("--tomcat-password", default=None, help="Set the timeout of HTTP requests.")
    group_configuration.add_argument("--tomcat-passwords-file", default=None, help="Set the timeout of HTTP requests.")

    group_targets_source = parser.add_argument_group("Targets")
    group_targets_source.add_argument("-tf", "--targets-file", default=None, type=str, help="Path to file containing a line by line list of targets.")
    group_targets_source.add_argument("-tt", "--target", default=[], type=str, action='append', help="Target IP, FQDN or CIDR")
    group_targets_source.add_argument("-tp", "--target-ports", default="80,443,8080,8081,9080,9081,10080", type=str, help="Target ports to scan top search for Apache Tomcat servers.")
    group_targets_source.add_argument("-ad", "--auth-domain", default="", type=str, help="Windows domain to authenticate to.")
    group_targets_source.add_argument("-ai", "--auth-dc-ip", default=None, type=str, help="IP of the domain controller.")
    group_targets_source.add_argument("-au", "--auth-user", default=None, type=str, help="Username of the domain account.")
    group_targets_source.add_argument("-ap", "--auth-password", default=None, type=str, help="Password of the domain account.")
    group_targets_source.add_argument("-ah", "--auth-hashes", default=None, type=str, help="LM:NT hashes to pass the hash for this user.")
    group_targets_source.add_argument("--ldaps", default=False, action="store_true", help="Use LDAPS (default: False)")
    group_targets_source.add_argument("--subnets", default=False, action="store_true", help="Get all subnets from the domain and use them as targets (default: False)")

    args = parser.parse_args()

    if (args.targets_file is None) and (len(args.target) == 0) and (args.auth_user is None and (args.auth_password is None or args.auth_hashes is None)):
        parser.print_help()
        print("\n[!] No targets specified.")
        sys.exit(0)

    if (args.auth_password is not None) and (args.auth_hashes is not None):
        parser.print_help()
        print("\n[!] Options --auth-password/--auth-hashes are mutually exclusive.")
        sys.exit(0)

    if (args.auth_dc_ip is None) and (args.auth_user is not None and (args.auth_password is not None or args.auth_hashes is not None)):
        parser.print_help()
        print("\n[!] Option --auth-dc-ip is required when using --auth-user, --auth-password, --auth-hashes, --auth-domain")
        sys.exit(0)

    return args


def main():
    options = parseArgs()

    config = Config()
    config.set_debug_mode(options.debug)
    config.set_request_available_schemes(only_http=options.only_http, only_https=options.only_https)
    config.set_request_timeout(options.request_timeout)
    config.set_request_proxies(options.proxy_ip, options.proxy_port)
    # config.set_request_no_check_certificate(options.no_check_certificate)
    config.set_list_cves_mode(options.list_cves)

    config.load_credentials_from_options(options.tomcat_username, options.tomcat_password, options.tomcat_usernames_file, options.tomcat_passwords_file)

    vulns_db = VulnerabilitiesDB(config=config)
    reporter = Reporter(config=config, vulns_db=vulns_db)

    # Parsing targets and ports
    targets = load_targets(options, config)
    ports = load_ports(options, config)
    if len(targets) != 0:
        if len(ports) != 0:
            if options.proxy_ip is not None and options.proxy_port is not None:
                print("[+] Targeting %d ports on %d targets through proxy %s:%d" % (len(ports), len(targets), options.proxy_ip, options.proxy_port))
            else:
                print("[+] Targeting %d ports on %d targets" % (len(ports), len(targets)))

            # Exploring targets
            if len(targets) != 0 and options.threads != 0:
                print("[+] Searching for Apache Tomcats servers on specified targets ...")
                monitor_data = {"actions_performed": 0, "total": (len(targets)*len(ports)), "lock": threading.Lock()}
                with ThreadPoolExecutor(max_workers=min(options.threads, 1+monitor_data["total"])) as tp:
                    tp.submit(monitor_thread, reporter, config, monitor_data)
                    for target in targets:
                        for port in ports:
                            tp.submit(scan_worker, target, port, reporter, config, monitor_data)
                print("[+] All done!")

            if options.export_xlsx is not None:
                reporter.export_xlsx(options.export_xlsx)

            if options.export_json is not None:
                reporter.export_json(options.export_json)

            if options.export_sqlite is not None:
                reporter.export_sqlite(options.export_sqlite)
        else:
            print("[!] Cannot start scan: no ports loaded.")
    else:
        print("[!] Cannot start scan: no targets loaded.")


if __name__ == '__main__':
    main()
