import urllib.request
import json
import pprint
import apiHelpers as acc
import requests


ping_url = "http://cs302.kiwi.land/api/ping"

keys = acc.get_keys()
header = acc.create_header("jall229", "jacoballen4534_205023320")

signature_hex_str = acc.sign_message(keys["pubkey_hex_str"])

payload = {
    "pubkey": keys["pubkey_hex_str"],
    "signature": signature_hex_str
}
byte_payload = bytes(json.dumps(payload), "utf-8")
req = urllib.request.Request(url=ping_url, data=byte_payload, headers=header)

JSON_object = acc.query_server(req)

pprint.pprint(JSON_object)