#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Reporter.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2022

import json
import os.path
import xlsxwriter


class Reporter(object):
    """
    Documentation for class Reporter
    """

    data = {}

    def __init__(self, config):
        super(Reporter, self).__init__()
        self.config = config

    def report_result(self, computer_ip, computer_port, tomcat_version, manager_accessible, default_credentials, cves):
        computer_port = str(computer_port)
        if computer_ip not in self.data.keys():
            self.data[computer_ip] = {}
        if str(computer_port) not in self.data[computer_ip].keys():
            self.data[computer_ip][computer_port] = {}
        self.data[computer_ip][computer_port]["computer_ip"] = computer_ip
        self.data[computer_ip][computer_port]["computer_port"] = computer_port
        self.data[computer_ip][computer_port]["tomcat_version"] = tomcat_version
        self.data[computer_ip][computer_port]["manager_accessible"] = manager_accessible
        self.data[computer_ip][computer_port]["default_credentials"] = default_credentials
        self.data[computer_ip][computer_port]["cves"] = cves

    def export_xlsx(self, path_to_file):
        outdir = os.path.dirname(path_to_file)
        if len(outdir) != 0:
            if not os.path.exists(outdir):
                os.makedirs(os.path.dirname(path_to_file), exist_ok=True)

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
                data = [
                    computer[port]["computer_ip"],
                    computer[port]["computer_port"],
                    computer[port]["tomcat_version"],
                    str(computer[port]["manager_accessible"]).upper(),
                    computer[port]["default_credentials"],
                    computer[port]["cves"]
                ]
                worksheet.write_row(row_id, 0, data)
                row_id += 1
        worksheet.autofilter(0, 0, row_id, len(header_fields) - 1)
        workbook.close()

    def export_json(self, path_to_file):
        outdir = os.path.dirname(path_to_file)
        if len(outdir) != 0:
            if not os.path.exists(outdir):
                os.makedirs(os.path.dirname(path_to_file), exist_ok=True)
        f = open(path_to_file, 'w')
        f.write(json.dumps(self.data, indent=4))
        f.close()
