#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : test_environement.py
# Author             : Podalirius (@podalirius_)
# Date created       : 24 Jul 2022

import argparse
import os


instances = {
    "tomcat_8_5_81": "docker run --rm -d --name tomcat_8_5_81 -p 10001:8080 -v $(pwd)/versions/8.5.81/tomcat-users.xml:/usr/local/tomcat/conf/tomcat-users.xml tomcat:8.5.81-jdk8-corretto",
    "tomcat_7_0_59": "docker run --rm -d --name tomcat_7_0_59 -p 10002:8080 -v $(pwd)/versions/7.0.59/tomcat-users.xml:/usr/local/tomcat/conf/tomcat-users.xml tomcat:7.0.59",
    "tomcat_6_0_43": "docker run --rm -d --name tomcat_6_0_43 -p 10003:8080 -v $(pwd)/versions/6.0.43/tomcat-users.xml:/usr/local/tomcat/conf/tomcat-users.xml tomcat:6.0.43"
}


def parseArgs():
    parser = argparse.ArgumentParser(description="Description message")
    parser.add_argument("action", help='arg1 help message')
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help='Verbose mode. (default: False)')
    options = parser.parse_args()
    if options.action.lower() not in ["start", "stop"]:
        pass
    return options


if __name__ == '__main__':
    options = parseArgs()

    if options.action.lower() == "start":
        for key in instances.keys():
            cmd = instances[key]
            if options.verbose:
                print(cmd)
            print("[+] Starting %s" % key)
            os.system(cmd)
    elif options.action.lower() == "stop":
        cmd = "docker stop %s" % ' '.join([key for key in instances.keys()])
        if options.verbose:
            print(cmd)
        os.system(cmd)
