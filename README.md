![](./.github/banner.png)

<p align="center">
  A python script to scan for Apache Tomcat server vulnerabilities.
  <br>
  <img alt="PyPI" src="https://img.shields.io/pypi/v/apachetomcatscanner">
  <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/p0dalirius/ApacheTomcatScanner">
  <img alt="Python pip build" src="https://github.com/p0dalirius/ApacheTomcatScanner/actions/workflows/python-pip-build.yml/badge.svg">
  <a href="https://twitter.com/intent/follow?screen_name=podalirius_" title="Follow"><img src="https://img.shields.io/twitter/follow/podalirius_?label=Podalirius&style=social"></a>
  <a href="https://www.youtube.com/c/Podalirius_?sub_confirmation=1" title="Subscribe"><img alt="YouTube Channel Subscribers" src="https://img.shields.io/youtube/channel/subscribers/UCF_x5O7CSfr82AfNVTKOv_A?style=social"></a>
  <br>
</p>

## Features

 - [x] Multithreaded workers to search for Apache tomcat servers.
 - [x] Multiple target source possible:
   - [x] Retrieving list of computers from a Windows domain through an LDAP query to use them as a list of targets.
   - [x] Reading targets line by line from a file.
   - [x] Reading individual targets (IP/DNS/CIDR) from `-tt/--target` option. 
 - [x] Custom list of ports to test.
 - [x] Tests for `/manager/html` access and default credentials.
 - [x] List the CVEs of each version with the `--list-cves` option


## Installation

You can now install it from pypi (latest version is <img alt="PyPI" src="https://img.shields.io/pypi/v/apachetomcatscanner">) with this command:

```
sudo python3 -m pip install apachetomcatscanner
```

## Usage

```
$ ./ApacheTomcatScanner.py -h
Apache Tomcat Scanner v2.1 - by @podalirius_

usage: ApacheTomcatScanner.py [-h] [-v] [-C] [-T THREADS] [-PI PROXY_IP] [-PP PROXY_PORT] [-rt REQUEST_TIMEOUT] [-tf TARGETS_FILE] [-tt TARGET] [-tp TARGET_PORTS] [-ad AUTH_DOMAIN] [-ai AUTH_DC_IP] [-au AUTH_USER] [-ap AUTH_PASSWORD]
                              [-ah AUTH_HASH]

A python script to scan for Apache Tomcat server vulnerabilities.

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose mode. (default: False)
  -C, --list-cves       List CVE ids affecting each version found. (default: False)
  -T THREADS, --threads THREADS
                        Number of threads (default: 5)

  -PI PROXY_IP, --proxy-ip PROXY_IP
                        Proxy IP.
  -PP PROXY_PORT, --proxy-port PROXY_PORT
                        Proxy port
  -rt REQUEST_TIMEOUT, --request-timeout REQUEST_TIMEOUT

  -tf TARGETS_FILE, --targets-file TARGETS_FILE
  -tt TARGET, --target TARGET
                        Target IP, FQDN or CIDR
  -tp TARGET_PORTS, --target-ports TARGET_PORTS
                        Target ports to scan top search for Apache Tomcat servers.
  -ad AUTH_DOMAIN, --auth-domain AUTH_DOMAIN
  -ai AUTH_DC_IP, --auth-dc-ip AUTH_DC_IP
  -au AUTH_USER, --auth-user AUTH_USER
  -ap AUTH_PASSWORD, --auth-password AUTH_PASSWORD
  -ah AUTH_HASH, --auth-hash AUTH_HASH
```

## Example

![](./.github/example.png)

You can also list the CVEs of each version with the `--list-cves` option:

![](./.github/example_list_cves.png)

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.
