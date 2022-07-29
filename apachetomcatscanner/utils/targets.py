#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : targets.py
# Author             : Podalirius (@podalirius_)
# Date created       : 29 Jul 2022


def get_computers_from_domain(auth_domain, auth_username, auth_password, auth_hashes):
    auth_lm_hash = ""
    auth_nt_hash = ""
    if auth_hashes is not None:
        if ":" in auth_hashes:
            auth_lm_hash = auth_hashes.split(":")[0]
            auth_nt_hash = auth_hashes.split(":")[1]
        else:
            auth_nt_hash = auth_hashes

    ldap_server, ldap_session = init_ldap_session(
        args=args,
        domain=auth_domain,
        username=auth_username,
        password=auth_password,
        lmhash=auth_lm_hash,
        nthash=auth_nt_hash
    )

    print("[>] Extracting all computers ...")

    targets = []
    target_dn = ldap_server.info.other["defaultNamingContext"]
    ldap_session.search(target_dn, "(objectCategory=computer)", attributes=["dNSHostName"])
    for entry in ldap_session.response:
        if entry['type'] != 'searchResEntry':
            continue
        targets.append(entry["attributes"]['dNSHostName'])

    print("[+] Found %d computers in the domain." % len(targets))

    return targets