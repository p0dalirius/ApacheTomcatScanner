![](./.github/banner.png)

<p align="center">
  A python script to scan for Apache Tomcat server vulnerabilities.
  <br>
  <img alt="PyPI" src="https://img.shields.io/pypi/v/apachetomcatscanner">
  <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/p0dalirius/ApacheTomcatScanner">
  <a href="https://twitter.com/intent/follow?screen_name=podalirius_" title="Follow"><img src="https://img.shields.io/twitter/follow/podalirius_?label=Podalirius&style=social"></a>
  <a href="https://www.youtube.com/c/Podalirius_?sub_confirmation=1" title="Subscribe"><img alt="YouTube Channel Subscribers" src="https://img.shields.io/youtube/channel/subscribers/UCF_x5O7CSfr82AfNVTKOv_A?style=social"></a>
  <br>
</p>

## Features

 - [x] TBD

## Usage

```
$ ./ApacheTomcatScanner.py  -h
Apache Tomcat Scanner v1.2 - by @podalirius_

usage: ApacheTomcatScanner.py [-h] [-v] [-T THREADS] [-PI PROXY_IP] [-PP PROXY_PORT] [-tf TARGETS_FILE] [-tt TARGET]
                              [-tp TARGET_PORTS] [-ad AUTH_DOMAIN] [-au AUTH_USER] [-ap AUTH_PASSWORD]
                              [-ah AUTH_HASH]

A python script to scan for Apache Tomcat server vulnerabilities.

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose mode. (default: False)
  -T THREADS, --threads THREADS
                        Number of threads (default: 5)

  -PI PROXY_IP, --proxy-ip PROXY_IP
  -PP PROXY_PORT, --proxy-port PROXY_PORT

  -tf TARGETS_FILE, --targets-file TARGETS_FILE
  -tt TARGET, --target TARGET
                        Target IP, FQDN or CIDR
  -tp TARGET_PORTS, --target-ports TARGET_PORTS
                        Target ports to scan top search for Apache Tomcat servers.
  -ad AUTH_DOMAIN, --auth-domain AUTH_DOMAIN
  -au AUTH_USER, --auth-user AUTH_USER
  -ap AUTH_PASSWORD, --auth-password AUTH_PASSWORD
  -ah AUTH_HASH, --auth-hash AUTH_HASH
```

## Example

![](./.github/example.png)

---

## Development roadmap

 - [ ] Core
    + [ ] Loading database in JSON format with references and affected versions and OSes of each vulnerability on Apache Tomcat
    + [x] Use a proxy with `--proxy-ip` and `--proxy-port`
   
 - [x] Targets source
    + [x] Accepting targets of type CIDR, DNS and IP
    + [x] Retreive list of targets from a file (`--targets-file`)
    + [x] Retreive list of targets in a Windows domain (`--auth-domain`, `--auth-user`, `--auth-password` / `--auth-hash`) through a LDAP query listing all computers of the domain.

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.
