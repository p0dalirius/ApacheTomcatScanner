#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Reporter.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2022

import json
import os.path
import sqlite3
import traceback
import xlsxwriter


class Reporter(object):
    """
    Documentation for class Reporter
    """

    data = {}

    def __init__(self, config, vulns_db):
        super(Reporter, self).__init__()
        self.config = config
        self.vulns_db = vulns_db
        self._new_results = []

    def report_result(self, computer_ip, computer_port, result, credentials_found):
        computer_port = str(computer_port)

        finding = result.copy()
        finding["computer_ip"] = computer_ip
        finding["computer_port"] = computer_port
        finding["credentials_found"] = credentials_found

        finding["cves"] = self.vulns_db.get_vulnerabilities_of_version_sorted_by_criticity(finding["version"], colors=False, reverse=True)

        if computer_ip not in self.data.keys():
            self.data[computer_ip] = {}
        if str(computer_port) not in self.data[computer_ip].keys():
            self.data[computer_ip][computer_port] = {}
        self.data[computer_ip][computer_port] = finding
        self._new_results.append(finding)

    def print_new_results(self):
        try:
            for finding in self._new_results:
                if finding["manager_accessible"]:
                    if self.config.no_colors:
                        prompt = "[>] [Apache Tomcat/%s] on %s:%s (manager: accessible) on %s "
                    else:
                        prompt = "[>] [Apache Tomcat/\x1b[1;95m%s\x1b[0m] on \x1b[1;93m%s\x1b[0m:\x1b[1;93m%s\x1b[0m (manager: \x1b[1;92maccessible\x1b[0m) on \x1b[4;94m%s\x1b[0m "
                    print(prompt % (finding["version"], finding["computer_ip"], finding["computer_port"], finding["manager_url"]))

                    if len(finding["credentials_found"]) != 0:
                        for statuscode, creds in finding["credentials_found"]:
                            if len(creds["description"]) != 0:
                                if self.config.no_colors:
                                    prompt = "  | Valid user: %s | password: %s | %s"
                                else:
                                    prompt = "  | Valid user: \x1b[1;92m%s\x1b[0m | password: \x1b[1;92m%s\x1b[0m | \x1b[94m%s\x1b[0m"
                                print(prompt % (creds["username"], creds["password"], creds["description"]))
                            else:
                                if self.config.no_colors:
                                    prompt = "  | Valid user: %s | password: %s"
                                else:
                                    prompt = "  | Valid user: \x1b[1;92m%s\x1b[0m | password: \x1b[1;92m%s\x1b[0m"
                                print(prompt % (creds["username"], creds["password"]))

                else:
                    if self.config.no_colors:
                        prompt = "[>] [Apache Tomcat/%s] on %s:%s (manager: not accessible)"
                    else:
                        prompt = "[>] [Apache Tomcat/\x1b[1;95m%s\x1b[0m] on \x1b[1;93m%s\x1b[0m:\x1b[1;93m%s\x1b[0m (manager: \x1b[1;91mnot accessible\x1b[0m)\x1b[0m "
                    print(prompt % (finding["version"], finding["computer_ip"], finding["computer_port"]))

                # List of cves
                if self.config.list_cves_mode == True and self.config.show_cves_descriptions_mode == False:
                    cve_list = self.vulns_db.get_vulnerabilities_of_version_sorted_by_criticity(finding["version"], colors=True, reverse=True)
                    cve_list = [cve_colored for cve_colored, cve_content in cve_list]
                    if len(cve_list) != 0:
                        print("  | CVEs: %s" % ', '.join(cve_list))
                elif self.config.show_cves_descriptions_mode == True:
                    cve_list = self.vulns_db.get_vulnerabilities_of_version_sorted_by_criticity(finding["version"], colors=True, reverse=True)
                    for cve_colored, cve_content in cve_list:
                        print("  | %s: %s" % (cve_colored, cve_content["description"]))

                self._new_results.remove(finding)
        except Exception as e:
            if self.config.debug_mode:
                print("[Error in %s] %s" % (__name__, e))
                traceback.print_exc()

    def export_xlsx(self, path_to_file):
        path_to_file = os.path.abspath(path_to_file)
        basepath = os.path.dirname(path_to_file)
        filename = os.path.basename(path_to_file)
        if basepath not in [".", ""]:
            if not os.path.exists(basepath):
                os.makedirs(basepath)
            path_to_file = basepath + os.path.sep + filename
        else:
            path_to_file = filename

        workbook = xlsxwriter.Workbook(path_to_file)
        worksheet = workbook.add_worksheet()

        header_format = workbook.add_format({'bold': 1})
        header_fields = ["Computer IP", "Port", "Apache tomcat version", "Manager accessible", "Default credentials found", "CVEs on this version"]
        for k in range(len(header_fields)):
            worksheet.set_column(k, k + 1, len(header_fields[k]) + 3)
        worksheet.set_row(0, 20, header_format)
        worksheet.write_row(0, 0, header_fields)

        row_id = 1
        for computername in self.data.keys():
            computer = self.data[computername]
            for _, finding in computer.items():
                cve_str = ', '.join([cve["cve"]["id"] for cve in finding["cves"]])
                credentials_str = ', '.join([f"{cred[1]} ({cred[0]})" for cred in finding["credentials_found"]])

                data = [
                    finding["computer_ip"],
                    finding["computer_port"],
                    finding["version"],
                    str(finding["manager_accessible"]).upper(),
                    credentials_str,
                    cve_str
                ]
                worksheet.write_row(row_id, 0, data)
                row_id += 1
        worksheet.autofilter(0, 0, row_id, len(header_fields) - 1)
        workbook.close()

    def export_json(self, path_to_file):
        path_to_file = os.path.abspath(path_to_file)
        basepath = os.path.dirname(path_to_file)
        filename = os.path.basename(path_to_file)
        if basepath not in [".", ""]:
            if not os.path.exists(basepath):
                os.makedirs(basepath)
            path_to_file = basepath + os.path.sep + filename
        else:
            path_to_file = filename
        f = open(path_to_file, 'w')
        f.write(json.dumps(self.data, indent=4))
        f.close()

    def export_sqlite(self, path_to_file):
        path_to_file = os.path.abspath(path_to_file)
        basepath = os.path.dirname(path_to_file)
        filename = os.path.basename(path_to_file)
        if basepath not in [".", ""]:
            if not os.path.exists(basepath):
                os.makedirs(basepath)
            path_to_file = basepath + os.path.sep + filename
        else:
            path_to_file = filename

        conn = sqlite3.connect(path_to_file)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS results(computer_ip VARCHAR(255), computer_port INTEGER, version VARCHAR(255), manager_accessible VARCHAR(255), credentials_found VARCHAR(255), cves INTEGER);")
        for computername in self.data.keys():
            computer = self.data[computername]
            for _, finding in computer.items():
                cve_str = ', '.join([cve["cve"]["id"] for cve in finding["cves"]])
                credentials_str = ', '.join([f"{cred[1]} ({cred[0]})" for cred in finding["credentials_found"]])

                cursor.execute("INSERT INTO results VALUES (?, ?, ?, ?, ?, ?)", (
                        finding["computer_ip"],
                        finding["computer_port"],
                        finding["version"],
                        str(finding["manager_accessible"]).upper(),
                        credentials_str,
                        cve_str
                    )
                )
        conn.commit()
        conn.close()
