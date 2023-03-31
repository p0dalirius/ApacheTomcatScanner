#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : update_db.py
# Author             : Podalirius (@podalirius_)
# Date created       : 5 Dec 2022


import json
import os
import re
import datetime
import requests
from bs4 import BeautifulSoup
import glob


def get_versions_order():
    dates_releases = {}
    releases_dates = {}
    for major_version in [3, 4, 5, 6, 7, 8, 9, 10, 11]:
        base_url = "https://archive.apache.org/dist/tomcat/tomcat-%d/" % major_version
        r = requests.get(base_url)
        matched = re.findall(b"((<a href=[^>]+>[^<]+</a>)[ \t\n]+([0-9]{4}-[0-9]{2}-[0-9]{2}[ \t\n]+[0-9]{2}:[0-9]{2}(:[0-9]{2})?))", r.content)
        for _, a, d, _ in matched:
            a = BeautifulSoup(a, "lxml").find('a')
            if a is not None:
                if a["href"].endswith("/"):
                    version = re.search("([0-9]+\.[0-9]+\.[0-9]+(-M[0-9]+)?)", a["href"])
                    if version is not None:
                        version = version.groups()[0]
                        release_date = datetime.datetime.strptime(d.decode('utf-8'), "%Y-%m-%d %H:%M")
                        release_date_ts = int(release_date.timestamp())

                        if release_date_ts not in dates_releases.keys():
                            dates_releases[release_date_ts] = []
                        dates_releases[release_date_ts].append(version)
                        dates_releases[release_date_ts] = list(set(dates_releases[release_date_ts]))

                        if version not in releases_dates.keys():
                            releases_dates[version] = []
                        releases_dates[version].append(release_date_ts)
                        releases_dates[version] = list(set(releases_dates[version]))
                    # else:
                    #     print("Skipped", a["href"])
    return dates_releases, releases_dates


def get_versions_in_range(dates_releases, releases_dates, version_start, version_stop):
    matching_versions = []
    if version_start in releases_dates.keys() and version_stop in releases_dates.keys():
        ts_version_start = min(releases_dates[version_start])
        ts_version_stop = max(releases_dates[version_stop])
        for tskey in dates_releases.keys():
            if ts_version_start <= tskey <= ts_version_stop:
                matching_versions += dates_releases[tskey]

    # Prepare filter
    common_start = ""
    for k in range(min(len(version_start), len(version_stop))):
        if version_stop[k] == version_start[k]:
            common_start += version_start[k]
        else:
            break
    # filter
    versions = []
    for version in matching_versions:
        if version.startswith(common_start):
            versions.append(version)

    return versions


def add_versions_ranges_from_description(dates_releases, releases_dates, cve_data):
    matched = re.findall('(([0-9]+\.[0-9]+\.[0-9]+(-M[0-9]+)?) (to|through) ([0-9]+\.[0-9]+\.[0-9]+(-M[0-9]+)?))', cve_data["description"])
    version_ranges = [(m[1], m[4]) for m in matched]

    for version_start, version_stop in version_ranges:
        versions_in_range = get_versions_in_range(dates_releases, releases_dates, version_start, version_stop)
        # print("Versions range %s ──> %s : %s" % (version_start, version_stop, versions_in_range))
        for version_tag in versions_in_range:
            matched = re.search("([0-9]+\.[0-9]+\.[0-9]+(-M[0-9]+)?)", version_tag)
            if matched is not None:
                Version, Update = matched.groups()
                cve_data["affected_versions"].append({
                    "tag": version_tag,
                    "version": Version,
                    "language": "*",
                    "update": Update,
                    "edition": "*"
                })

    # Unique set
    new_versions = []
    known_versions = []
    for av in cve_data["affected_versions"]:
        if av["tag"] not in known_versions:
            new_versions.append(av)
            known_versions.append(av["tag"])
    cve_data["affected_versions"] = new_versions
    return cve_data


def parse_vulns(vulnerabilities_in_this_ver, Version, Language, Update, Edition, CVES):
    r = requests.get("https://www.cvedetails.com/%s" % vulnerabilities_in_this_ver)
    soup = BeautifulSoup(r.content, 'lxml')

    table = soup.find('table', attrs={"id": "vulnslisttable"})
    for tr in table.findAll("tr"):
        tds = tr.findAll('td')
        if len(tds) == 15:
            id = tds[0].text.strip()

            cve_id = tds[1].text.strip()
            print("   [>] Parsing %s" % cve_id)
            cve_id_link = "https://www.cvedetails.com" + tds[1].find('a')['href']

            cwe_id = tds[2].text.strip()
            cwe_id_link = None
            if tds[2].find('a') is not None:
                cwe_id_link = "https://www.cvedetails.com" + tds[2].find('a')['href']

            if cve_id not in CVES.keys():
                CVES[cve_id] = {}

            if "cve" not in CVES[cve_id].keys():
                CVES[cve_id]["cve"] = {}
            number_of_exploits = tds[3].text.strip()
            CVES[cve_id]["cve"]["name"] = ""
            CVES[cve_id]["cve"]["id"] = cve_id
            CVES[cve_id]["cve"]["year"] = int(cve_id.split('-')[1])
            CVES[cve_id]["cve"]["vuln_type"] = tds[4].text.strip()
            CVES[cve_id]["cve"]["publish_date"] = tds[5].text.strip()
            CVES[cve_id]["cve"]["update_date"] = tds[6].text.strip()

            if "cvss" not in CVES[cve_id].keys():
                CVES[cve_id]["cvss"] = {}
            CVES[cve_id]["cvss"]["score"] = tds[7].text.strip()

            risk_levels = ["None", "Low", "Medium", "High", "Critical"]
            criticity = "None"
            if float(CVES[cve_id]["cvss"]["score"]) == 0:
                criticity = risk_levels[0]
            elif 0 < float(CVES[cve_id]["cvss"]["score"]) < 4:
                criticity = risk_levels[1]
            elif 4 <= float(CVES[cve_id]["cvss"]["score"]) < 7:
                criticity = risk_levels[2]
            elif 7 <= float(CVES[cve_id]["cvss"]["score"]) < 9:
                criticity = risk_levels[3]
            elif 9 <= float(CVES[cve_id]["cvss"]["score"]) < 10:
                criticity = risk_levels[4]

            CVES[cve_id]["cvss"]["criticity"] = criticity
            CVES[cve_id]["cvss"]["gained_access_level"] = tds[8].text.strip()
            CVES[cve_id]["cvss"]["access"] = tds[9].text.strip()
            CVES[cve_id]["cvss"]["complexity"] = tds[10].text.strip()
            CVES[cve_id]["cvss"]["confidentiality"] = tds[8].text.strip()
            CVES[cve_id]["cvss"]["integrity"] = tds[8].text.strip()
            CVES[cve_id]["cvss"]["availablility"] = tds[8].text.strip()

            if "affected_versions" not in CVES[cve_id].keys():
                CVES[cve_id]["affected_versions"] = []
            CVES[cve_id]["affected_versions"].append({
                "tag": (Version + '-' + Update if Update != '*' else Version),
                "version": Version,
                "language": Language,
                "update": Update,
                "edition": Edition
            })

            if "references" not in CVES[cve_id].keys():
                CVES[cve_id]["references"] = []
            CVES[cve_id]["references"].append("https://nvd.nist.gov/vuln/detail/%s" % cve_id)

            r = requests.get(cve_id_link)
            soup = BeautifulSoup(r.content, 'lxml')

            cvedetailssummary = soup.find('div', attrs={"class": "cvedetailssummary"})
            CVES[cve_id]["description"] = cvedetailssummary.text.strip().split('Publish Date : ')[0].strip()

            vulnrefstable = soup.find('table', attrs={"id": "vulnrefstable"})
            for tr in vulnrefstable.findAll('tr'):
                links = [a['href'] for a in tr.findAll('a')]
                for link in links:
                    CVES[cve_id]["references"].append(link)
            CVES[cve_id]["references"] = list(sorted(set(CVES[cve_id]["references"])))


if __name__ == '__main__':
    CVES = {}

    if os.path.exists("./vulnerabilities/"):
        for file in glob.glob("./vulnerabilities/*/*.json"):
            f = open(file, "r")
            data = json.loads(f.read())
            f.close()
            CVES[data["cve"]["id"]] = data

    r = requests.get("https://www.cvedetails.com/version-list/45/887/2/Apache-Tomcat.html?sha=1e26d2dc4f7319bbf6b0bf066415a3daf97151c8&order=1&trc=986")
    soup = BeautifulSoup(r.content, 'lxml')

    pagingb = soup.find('div', attrs={"id": "pagingb", "class": "paging"})
    pages = list(map(int, [a.text.strip() for a in pagingb.findAll('a')]))

    for page_number in pages:
        r = requests.get("https://www.cvedetails.com/version-list/45/887/%d/Apache-Tomcat.html?sha=1e26d2dc4f7319bbf6b0bf066415a3daf97151c8&order=1&trc=986" % page_number)
        soup = BeautifulSoup(r.content, 'lxml')

        table = soup.find('table', attrs={"class": "listtable"})
        print("[>] Parsing page %d/%d" % (page_number, pages[-1]))
        for tr in table.findAll("tr"):
            tds = tr.findAll('td')
            if len(tds) == 6:
                Version = tds[0].text.strip()
                Language = tds[1].text.strip()
                Update = tds[2].text.strip()
                Edition = tds[3].text.strip()
                Number_of_Vulnerabilities = int(tds[4].text.strip())
                links = tds[5].findAll('a')
                version_details = links[0]["href"]
                vulnerabilities_in_this_ver = links[1]["href"]
                if not (Version == "*" and Language == "*" and Update == "*" and Edition == "*"):
                    parse_vulns(vulnerabilities_in_this_ver, Version, Language, Update, Edition, CVES)

    dates_releases, releases_dates = get_versions_order()

    for cve_id, cve_data in CVES.items():
        cve_data = add_versions_ranges_from_description(dates_releases, releases_dates, cve_data)

        save_path = "./vulnerabilities/%d/%s.json" % (cve_data["cve"]["year"], cve_id)

        if not os.path.exists(os.path.dirname(save_path)):
            os.makedirs(os.path.dirname(save_path))

        if not os.path.exists(save_path):
            f = open(save_path, 'w')
            f.write(json.dumps(cve_data, indent=4))
            f.close()
        else:
            print("[+] Skipping %s because it already exists." % cve_id)
