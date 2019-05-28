import urllib.request
import json
import base64
import pprint
import nacl.encoding
import nacl.signing
import nacl.utils
import apiHelpers as acc


url = "http://cs302.kiwi.land/api/get_loginserver_record"

header = acc.create_header()
keys = acc.get_keys()

signature_hex_str = acc.sign_message(keys["pubkey_hex_str"])

req = urllib.request.Request(url=url, headers=header)
JSON_object = acc.query_server(req)
pprint.pprint(JSON_object)
