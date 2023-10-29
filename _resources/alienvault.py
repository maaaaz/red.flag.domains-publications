#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import argparse
import datetime
import pprint

import validators
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes

# Globals
VERSION = '1.0'
SECRET_ALIENVAULT_API_KEY = 'SECRET_ALIENVAULT_API_KEY'

# Options definition
parser = argparse.ArgumentParser(description="version: " + VERSION)
parser.add_argument('-a', '--action', help="Action to perform (default 'add')", choices = ['add'], type = str.lower, default = 'add')
parser.add_argument('-p', '--pulse_id', help='Pulse ID to perform the requested action', type = str.lower, required = True)
parser.add_argument('-i', '--input-file', help='Input file as a list of newline-separated IoC', required = True)

def make_indicator(entry, type):
    return { 'indicator': entry, 'type': type }

def make_indicators_from_file(fd_input):
    res = []
    
    for entry in fd_input:
        entry = entry.strip()
        
        if validators.domain(entry):
            res.append(make_indicator(entry, IndicatorTypes.DOMAIN.name))
        
        elif validators.ipv4(entry):
            res.append(make_indicator(entry, IndicatorTypes.IPv4.name))
            
        elif validators.ipv6(entry):
            res.append(make_indicator(entry, IndicatorTypes.IPv6.name))
            
        elif validators.email(entry):
            res.append(make_indicator(entry, IndicatorTypes.EMAIL.name))
            
        elif validators.url(entry):
            res.append(make_indicator(entry, IndicatorTypes.URL.name))
        
    #pprint.pprint(res)
    return res


def main():
    """
        Dat main
    """
    global parser
    options = parser.parse_args()
    
    otx = OTXv2(os.environ[SECRET_ALIENVAULT_API_KEY])
    
    with open(options.input_file, mode='r', encoding='utf-8') as fd_input:
        new_indicators = make_indicators_from_file(fd_input)
        response = otx.add_pulse_indicators(options.pulse_id, new_indicators)
        print(str(response))
    
    return

if __name__ == "__main__" :
    main()