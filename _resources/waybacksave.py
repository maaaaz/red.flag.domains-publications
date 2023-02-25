#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import argparse
import waybackpy

import code
import pprint

# Script version
VERSION = '1.1'

# Options definition
parser = argparse.ArgumentParser(description="version: " + VERSION)
parser.add_argument('-i', '--input-file', help='Input file as list of newline-separated FQDN', required = True)
parser.add_argument('-s', '--output-success', help='Output file to write successfully saved URL')
parser.add_argument('-f', '--output-failed', help='Output file to write failed attempts to save URL')

def dump_to_file(filename, content):
    with open(os.path.abspath(filename), mode='w', encoding='utf-8') as fd_output:
        for element in content:
            fd_output.write(element + '\n')
    
    return None

def waybackpy_save(url, successful_save_attempts, failed_save_attempts):
    res = True
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36'
    
    #print("[+] trying to save url:\t\t'%s'" % url)
    try:
        save_api = waybackpy.WaybackMachineSaveAPI(url=url, user_agent=user_agent, max_tries=5)
        save_api.save()
        
        if save_api.status_code == 200:
            print("[+] '%s' :\t successfully saved url\n----------" % url)
            successful_save_attempts.append(url)

    except Exception as e:
        failed_save_attempts.append(url)
        res = False
        print("[!] '%s' :\t exception '%s'\n----------" % (url, e.__class__.__name__))
    
    finally:
        return res

def submit(options):
    successful_save_attempts = []
    failed_save_attempts = []
    
    if os.path.isfile(options.input_file):
        urls = []
        with open(options.input_file, mode='r', encoding='utf-8') as fd_input:
            data = fd_input.read().splitlines()
            
            # punydecode
            data = list(map(lambda fqdn: fqdn.encode('idna').decode(), data))
        
        if len(data) >= 1:
            first_line = data[0]
            if not(first_line.startswith(('http://', 'https://'))):
                
                urls = list(map(lambda fqdn: "http://" + fqdn, data)) + list(map(lambda fqdn: "https://" + fqdn, data))
            else:
                urls = data
                
        if urls:
            print("[+] %s urls to save\n" % len(urls))
            
            for url in urls:
                waybackpy_save(url, successful_save_attempts, failed_save_attempts)
            
            print("\n[!] number of failed save attempts: %s" % len(failed_save_attempts))
            pprint.pprint(failed_save_attempts) if failed_save_attempts else None
    
            if options.output_success and successful_save_attempts:
                dump_to_file(options.output_success, successful_save_attempts)
            
            if options.output_failed and failed_save_attempts:
                dump_to_file(options.output_failed, failed_save_attempts)
    
    return

def main():
    global parser
    options = parser.parse_args()
    
    submit(options)
    
    return None

if __name__ == "__main__" :
    main()