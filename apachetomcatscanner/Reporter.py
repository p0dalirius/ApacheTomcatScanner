#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Reporter.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2022

import json
import os.path
import sqlite3
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

    def report_result(self, computer_ip, computer_port, tomcat_version, manager_accessible, credentials_found):
        computer_port = str(computer_port)

        finding = {}
        finding["computer_ip"] = computer_ip
        finding["computer_port"] = computer_port
        finding["tomcat_version"] = tomcat_version
        finding["manager_accessible"] = manager_accessible
        finding["credentials_found"] = credentials_found

        if computer_ip not in self.data.keys():
            self.data[computer_ip] = {}
        if str(computer_port) not in self.data[computer_ip].keys():
            self.data[computer_ip][computer_port] = {}
        self.data[computer_ip][computer_port] = finding
        self._new_results.append(finding)

    def print_new_results(self):
        try:
            for finding in self._new_results:

                # List of cves
                cve_str = ""
                if self.config.list_cves_mode == True:
                    cve_list = self.vulns_db.get_vulnerabilities_of_version_sorted_by_criticity(finding["tomcat_version"], colors=True, reverse=True)
                    if len(cve_list) != 0:
                        cve_str = "CVEs: %s" % ', '.join(cve_list)

                # credentials_str = "username:%s\npassword:%s" % (credentials_found[0][1]["username"], credentials_found[0][1]["password"])

                if finding["manager_accessible"]:
                    print("[>] [Apache Tomcat/\x1b[1;95m%s\x1b[0m] on \x1b[1;93m%s\x1b[0m:\x1b[1;93m%s\x1b[0m (manager:\x1b[1;92maccessible\x1b[0m) %s\x1b[0m " % (
                            finding["tomcat_version"],
                            finding["computer_ip"],
                            finding["computer_port"],
                            cve_str
                        )
                    )
                    if len(finding["credentials_found"]) != 0:
                        for statuscode, creds in finding["credentials_found"]:
                            if len(creds["description"]) != 0:
                                print("  | Valid user: \x1b[1;92m%s\x1b[0m | password:\x1b[1;92m%s\x1b[0m | \x1b[94m%s\x1b[0m" % (creds["username"], creds["password"], creds["description"]))
                            else:
                                print("  | Valid user: \x1b[1;92m%s\x1b[0m | password:\x1b[1;92m%s\x1b[0m" % (creds["username"], creds["password"]))

                else:
                    print("[>] [Apache Tomcat/\x1b[1;95m%s\x1b[0m] on \x1b[1;93m%s\x1b[0m:\x1b[1;93m%s\x1b[0m (manager:\x1b[1;91mnot accessible\x1b[0m) %s\x1b[0m " % (
                            finding["tomcat_version"],
                            finding["computer_ip"],
                            finding["computer_port"],
                            cve_str
                        )
                    )

                self._new_results.remove(finding)
        except Exception as e:
            if self.config.debug_mode:
                print("[Error in %s] %s" % (__name__, e))

    def export_xlsx(self, path_to_file):
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
            for port in computer.keys():
                cve_list = self.vulns_db.get_vulnerabilities_of_version_sorted_by_criticity(computer[port]["tomcat_version"], colors=False, reverse=True)
                cve_str = ', '.join([cve["cve"]["id"] for cve in cve_list])

                data = [
                    computer[port]["computer_ip"],
                    computer[port]["computer_port"],
                    computer[port]["tomcat_version"],
                    str(computer[port]["manager_accessible"]).upper(),
                    computer[port]["default_credentials"],
                    cve_str
                ]
                worksheet.write_row(row_id, 0, data)
                row_id += 1
        worksheet.autofilter(0, 0, row_id, len(header_fields) - 1)
        workbook.close()

    def export_json(self, path_to_file):
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
        cursor.execute("CREATE TABLE IF NOT EXISTS results(computer_ip VARCHAR(255), computer_port INTEGER, tomcat_version VARCHAR(255), manager_accessible VARCHAR(255), default_credentials VARCHAR(255), cves INTEGER);")
        for computername in self.data.keys():
            computer = self.data[computername]
            for port in computer.keys():
                cve_list = self.vulns_db.get_vulnerabilities_of_version_sorted_by_criticity(computer[port]["tomcat_version"], colors=False, reverse=True)
                cve_str = ', '.join([cve["cve"]["id"] for cve in cve_list])

                cursor.execute("INSERT INTO results VALUES (?, ?, ?, ?, ?, ?)", (
                        computer[port]["computer_ip"],
                        computer[port]["computer_port"],
                        computer[port]["tomcat_version"],
                        str(computer[port]["manager_accessible"]).upper(),
                        computer[port]["default_credentials"],
                        cve_str
                    )
                )
        conn.commit()
        conn.close()
