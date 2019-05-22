import urllib.request
import json
import base64
import pprint
import nacl.encoding
import nacl.signing
import nacl.utils
import apiHelpers as acc

check_pup_key_url = "http://cs302.kiwi.land/api/check_pubkey"
header = acc.create_header()
keys = acc.get_keys()

signature_hex_str = acc.sign_message(keys["pubkey_hex_str"] + acc.username)

check_pup_key_url = str(check_pup_key_url) + "?pubkey=" + \
                    str("b9eba910b59549774d55d3ce49a7b4d46ab5e225cdcf2ac388cf356b5928b6bc")#someones pubkey
# check_pup_key_url = str(check_pup_key_url) + "?pubkey=" + str(keys["pubkey_hex_str"]) #my pubkey
req = urllib.request.Request(url=check_pup_key_url, headers=header)
JSON_object = acc.query_server(req)

pprint.pprint(JSON_object)
