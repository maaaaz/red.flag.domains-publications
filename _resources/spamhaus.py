#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import functools
import concurrent.futures
import requests
import datetime
import time

import code
import pprint

from w3lib.url import safe_url_string
import validators

# Globals
VERSION = '1.0'

SPAMHAUS_API_BASE_URL = 'https://submit.spamhaus.org/portal/api/v1/'
SECRET_SPAMHAUS_API_KEY_BEARER = {"Authorization": "Bearer " + os.environ['SECRET_SPAMHAUS_API_KEY']}

SPAMHAUS_API_MAX_REQUEST_ONE_MINUTE = 30
SPAMHAUS_API_REMAINING_CALLS = SPAMHAUS_API_MAX_REQUEST_ONE_MINUTE
SPAMHAUS_API_TIMETOWAIT = SPAMHAUS_API_MAX_REQUEST_ONE_MINUTE

ACTION_SUBMIT = 'submit'
ACTION_GET_THREATS_TYPES = 'get_threats_types'
ACTION_GET_SUBS_LIST = 'get_subs_list'
ACTION_GET_SUBS_COUNTER = 'get_subs_counter'
ACTIONS_LIST = [ACTION_SUBMIT, ACTION_GET_THREATS_TYPES, ACTION_GET_SUBS_LIST, ACTION_GET_SUBS_COUNTER]

# Options definition
parser = argparse.ArgumentParser(description="version: " + VERSION)
common_group = parser.add_argument_group('common parameters')
common_group.add_argument('-a', '--action', help = 'Action to do on Spamhaus (default \'submit\')', choices = ACTIONS_LIST, type=str.lower, default = ACTION_SUBMIT)

action_submit_group = parser.add_argument_group("'submit' action parameters")
action_submit_group.add_argument('-i', '--input-file', help='Input file (list of newline-separated FQDN or URL or IP or email address)', required = False)
action_submit_group.add_argument('-r', '--reason', help='Reason to use (max length 255 characters)', required = False)

def print_horizontal_bar(number=80):
    print('-' * number)

def make_payload(options, threat_type, object, reason='It is malicious !'):
    elem = {}
    
    reason = options.reason if options.reason else reason
    if len(reason) <= 255 : 
        elem = {'threat_type': '%s' % threat_type,
                'reason': '%s' % reason,
                'source': {'object': '%s' % object}
               }
    else:
        print('[!] error while submitting indicators => length of "reason" is higher (%s) than the limit of 255 chars' % len(reason))
    
    return elem

def make_api_submit_request(url_endpoint, req_data):
    global SPAMHAUS_API_MAX_REQUEST_ONE_MINUTE, SPAMHAUS_API_REMAINING_CALLS, SPAMHAUS_API_TIMETOWAIT
    
    if SPAMHAUS_API_REMAINING_CALLS < 2:
        print('[!] Sleeping for "%s" seconds.\tIt is currently "%s" UTC' % (SPAMHAUS_API_TIMETOWAIT, datetime.datetime.now(datetime.UTC).replace(tzinfo=datetime.timezone.utc).isoformat()))
        time.sleep(SPAMHAUS_API_TIMETOWAIT)
        print('[!] Sleeping finished.\t\tIt is currently "%s" UTC' % datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
        SPAMHAUS_API_REMAINING_CALLS = SPAMHAUS_API_MAX_REQUEST_ONE_MINUTE
        
    req = requests.post(url_endpoint, headers=SECRET_SPAMHAUS_API_KEY_BEARER, json=req_data)
    req_headers = dict(req.headers)

    SPAMHAUS_API_REMAINING_CALLS = SPAMHAUS_API_REMAINING_CALLS - 1
    
    if 'X-Ratelimit-Remaining' in req_headers:
        SPAMHAUS_API_REMAINING_CALLS = int(req_headers['X-Ratelimit-Remaining'])
    
    """
    if 'X-Ratelimit-Reset' in req_headers:
        SPAMHAUS_API_TIMETOWAIT = int(req_headers['X-Ratelimit-Reset'])
    """
    
    return req

def spamhaus_get_actions(options):
    retval = os.EX_OK
    
    action = ''
    if options.action == ACTION_GET_THREATS_TYPES:
        action = 'lookup/threats-types'
    
    elif options.action == ACTION_GET_SUBS_COUNTER:
        action = 'submissions/count'
    
    elif options.action == ACTION_GET_SUBS_LIST:
        action = 'submissions/list'
        
    if action:
        url_endpoint = SPAMHAUS_API_BASE_URL + action
        req = requests.get(url_endpoint, headers=SECRET_SPAMHAUS_API_KEY_BEARER)
        
        if req.ok:
            pprint.pprint(req.json(), indent=2)
            
        else:
            print("[!] error while getting action")
            pprint.pprint(req.status_code)
            print(req.content)
            
            retval = os.EX_DATAERR
    
    return retval

def spamhaus_submit(options):
    retval = os.EX_OK
    
    url_base_endpoint = SPAMHAUS_API_BASE_URL + 'submissions/add/'
        
    malicious_url = []
    
    if os.path.isfile(options.input_file):
        with open(options.input_file, mode='r', encoding='utf-8') as fd_input:
            for entry in fd_input:
                entry = entry.strip()
                
                req_data = None
                if validators.domain(entry):
                    url_endpoint = url_base_endpoint + 'domain'
                    req_data = make_payload(options, 'scam', entry)
                
                elif validators.url(entry):
                    url_endpoint = url_base_endpoint + 'url'
                    req_data = make_payload(options, 'phish', entry)
                
                elif validators.ipv4(entry) or validators.ipv6(entry):
                    url_endpoint = url_base_endpoint + 'ip'
                    req_data = make_payload(options, 'spam', entry)
                
                elif validators.email(entry):
                    url_endpoint = url_base_endpoint + 'domain'
                    domain_from_mail_address = entry[entry.index('@') + 1 :]
                    
                    if validators.domain(domain_from_mail_address):
                        req_data = make_payload(options, 'scam', domain_from_mail_address)
                
                if req_data:
                    pprint.pprint(req_data)
                    req = make_api_submit_request(url_endpoint, req_data)
                    if req.ok:
                        req_json = req.content
                        try:
                            req_json = req.json()
                        except:
                            pass
                        finally:
                            print("[+] Spamhaus submit request successful")
                            pprint.pprint(req_json)
                            print_horizontal_bar()
                        
                    else:
                        print("[!] error while submitting to Spamhaus")
                        pprint.pprint(req.status_code)
                        print(req.content)
                        print(req.headers)
                        print_horizontal_bar()
    
    else:
        retval = os.EX_NOINPUT
        
    return retval

def main():
    global parser
    options = parser.parse_args()
    
    if options.action == ACTION_SUBMIT and options.input_file:
        sys.exit(spamhaus_submit(options))
    
    elif options.action == ACTION_SUBMIT and not(options.input_file):
        parser.error('[!] Please specify an input file for the "submit" action !')
    
    elif (options.action == ACTION_GET_THREATS_TYPES) or (options.action == ACTION_GET_SUBS_COUNTER) or (options.action == ACTION_GET_SUBS_LIST):
        sys.exit(spamhaus_get_actions(options))

if __name__ == "__main__" :
    main()
