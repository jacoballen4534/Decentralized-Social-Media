import urllib.request
import json
import base64
import pprint
import nacl.encoding
import nacl.signing
import nacl.utils
import accountParameters as acc


url = "http://cs302.kiwi.land/api/get_loginserver_record"

header = acc.create_header()
keys = acc.get_keys()

req = urllib.request.Request(url=url, headers=header)
JSON_object = acc.query_server(req)
pprint.pprint(JSON_object)
