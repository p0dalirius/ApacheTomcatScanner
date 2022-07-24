#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Target.py
# Author             : Podalirius (@podalirius_)
# Date created       : 24 Jul 2022

class Target(object):
    """
    Documentation for class Target
    """

    def __init__(self, target_host, target_port=8080):
        super(Target, self).__init__()
        self.target_host = target_host
        self.target_port = target_port

