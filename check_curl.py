#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
A Python script to do a curl check in Icinga2.
License: MIT
"""

from argparse import ArgumentParser
import requests
import urllib3

__author__  = 'Andreas Teubner'
__version__ = '1.2.0'
__license__ = 'MIT'

def parse_args():
    parser = ArgumentParser(description='A Python script to do a curl check in Icinga2.')

    parser.add_argument("--content", help="The content expected in the response", default=None)
    parser.add_argument("--data", help="HTTP GET/POST data", default=None)
    parser.add_argument("--domain", help="The Domain to connect with", default=None)
    parser.add_argument("--header", help="Pass custom header(s) to server")
    parser.add_argument("--interface", help="Use network INTERFACE (or address)")
    parser.add_argument("--request_type", help="Is this a GET or a POST request?")
    parser.add_argument("--uri", help="The URI to append to Domain")
    parser.add_argument("--version", action="version", version=__version__, help="Show version number")

    return parser.parse_args()

def get_status(content, status_code, status_text):
    if status_code == 200 and content in status_text:
        print(f'OK - {status_code} - URL or service reachable and content exists in response')
        exit(0)
    elif status_code == 200 and (content == None or content == ""):
        print(f'OK - {status_code} - URL or service reachable')
        exit(0)
    elif status_code != 200 and content in status_text and not (content == None or content == ""):
        print(f'OK - {status_code} - URL or service answers with Errorcode, but expected content exists in response')
        exit(0)
    elif status_code == 200 and content not in status_text:
        print(f'WARNING - {status_code} - URL or service reachable, but content does not exist in response')
        exit(1)
    else:
        print(f'CRITICAL - {status_code} - There is an error to reach URL or service')
        exit(2)

def set_source_address(interface, curl_connection):
    def set_interface(address, timeout, *args, **kw):
        source_address = (interface, 0)

        return curl_connection(address, timeout=timeout, source_address=source_address)

    return set_interface

def main(args):

    content = ""
    curl_connection = ""
    curl_session = ""
    data = ""
    domain = ""
    header = {'Connection':'close'}
    interface = ""
    request_type = "POST"
    status_code = 0
    status_text = ""
    uri = ""

    curl_session = requests.Session()
    curl_session.verify = False
    curl_connection = urllib3.util.connection.create_connection

    # DEBUG variables
    #print(f'\nContent:\t{content}\nData:\t\t{data}\nDomain:\t\t{domain}\nHeader:\t\t{header}\nInterface:\t{interface}\nURI:\t\t{uri}\n')

    if args.content != None:
        content = args.content

    if args.data != None:
        data = args.data.translate({ord(c): None for c in '\\'})

    if args.domain != None:
        domain = args.domain

    if args.header != None:
        lines = args.header.split(',')
        for line in lines:
            if ":" in line:
                key_value = line.split(':')
                header.update({key_value[0].strip(): key_value[1].strip()})

    if args.interface != None:
        interface = args.interface

    if args.request_type != None:
        request_type = args.request_type

    if args.uri != None:
        uri = args.uri

    # DEBUG variables
    #print(f'\nContent:\t{content}\nData:\t\t{data}\nDomain:\t\t{domain}\nHeader:\t\t{header}\nInterface:\t{interface}\nURI:\t\t{uri}\n')

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    urllib3.util.connection.create_connection = set_source_address(interface, curl_connection)

    try:
        if request_type == "GET":
            response = curl_session.get(domain+uri, headers=header, data=data, timeout=5, verify=False)
        else:
            response = curl_session.post(domain+uri, headers=header, data=data, timeout=5, verify=False)
        response.raise_for_status()
        status_code = response.status_code
        status_text = response.text
    except requests.exceptions.HTTPError as errh:
        get_status(content, errh.response.status_code, errh.response.text)
    except requests.exceptions.Timeout as errt:
        get_status(content, 0, errt.response.text)
    except requests.exceptions.ConnectionError as errc:
        get_status(content, 0, "Error")
    except requests.exceptions.RequestException as err:
        get_status(content, err.response.status_code, err.response.text)
    finally:
        curl_session.close()

    get_status(content, status_code, status_text)

if __name__ == "__main__":
    args = parse_args()
    main(args)
