import pprint
import urllib.request
import json
import apiHelpers as acc


add_pup_key_url = "http://cs302.kiwi.land/api/add_pubkey"

header = acc.create_header()
keys = acc.get_keys()
signature_hex_str = acc.sign_message(keys["pubkey_hex_str"] + acc.username)


payload = {
    "pubkey": keys["pubkey_hex_str"],
    "username": acc.username,
    "signature": signature_hex_str
}

byte_payload = bytes(json.dumps(payload), "utf-8")

req = urllib.request.Request(url=add_pup_key_url, data=byte_payload, headers=header)
JSON_object = acc.query_server(req)

pprint.pprint(JSON_object)