#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : VulnerabilitiesDB.py
# Author             : Podalirius (@podalirius_)
# Date created       : 24 Jul 2022

import glob
import json
import os


class VulnerabilitiesDB(object):
    """
    Documentation for class VulnerabilitiesDB
    """

    def __init__(self, config):
        super(VulnerabilitiesDB, self).__init__()
        self.config = config
        self.cves = {}
        self.versions_to_cves = {}
        self.load()
    
    def load(self):
        self.cves = {}
        self.config.debug("Loading CVEs from JSON database ...")
        # Load all CVEs from JSON files
        for cve_json_file in glob.glob('%s/vulnerabilities/*/CVE-*.json' % os.path.dirname(__file__)):
            try:
                f = open(cve_json_file, 'r')
                cve = json.loads(f.read())
                f.close()

                if "cve" in cve.keys():
                    if "id" in cve["cve"].keys():
                        self.cves[cve["cve"]["id"]] = cve
            except Exception as e:
                pass
        self.config.debug("Loaded %d CVEs!" % len(self.cves.keys()))

        # Construct reverse lookup database from version to CVEs
        if len(self.cves.keys()) != 0:
            for cve_id, cve_data in self.cves.items():
                for version in cve_data["affected_versions"]:
                    if version["tag"] not in self.versions_to_cves.keys():
                        self.versions_to_cves[version["tag"]] = []
                    self.versions_to_cves[version["tag"]].append(cve_data)

    def get_vulnerabilities_of_version_sorted_by_criticity(self, version_tag, colors=False, reverse=False):
        colored_criticity = {
            "None": "\x1b[1;48;2;83;170;51;97m%s\x1b[0m",
            "Low": "\x1b[1;48;2;255;203;13;97m%s\x1b[0m",
            "Medium": "\x1b[1;48;2;249;160;9;97m%s\x1b[0m",
            "High": "\x1b[1;48;2;233;61;3;97m%s\x1b[0m",
            "Critical": "\x1b[1;48;2;45;45;45;97m%s\x1b[0m"
        }
        vulnerabilities = []
        if version_tag in self.versions_to_cves.keys():
            vulnerabilities = self.versions_to_cves[version_tag]
            vulnerabilities = sorted(vulnerabilities, key=lambda cve: cve["cvss"]["score"], reverse=reverse)
            if colors:
                vulnerabilities = [
                    colored_criticity[vuln["cvss"]["criticity"]] % vuln["cve"]["id"]
                    for vuln in vulnerabilities
                ]
        return vulnerabilities

    def get_vulnerabilities_of_version_sorted_by_year(self, version_tag, reverse=False):
        vulnerabilities = []
        if version_tag in self.versions_to_cves.keys():
            vulnerabilities = self.versions_to_cves[version_tag]
            vulnerabilities = sorted(vulnerabilities, key=lambda cve: cve["cve"]["year"], reverse=reverse)
        return vulnerabilities
