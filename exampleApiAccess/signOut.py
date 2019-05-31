import urllib.request
import json
import pprint
import accountParameters as acc


url = "http://cs302.kiwi.land/api/report"
header = acc.create_header()
keys = acc.get_keys()

signature_hex_str = acc.sign_message(keys["pubkey_hex_str"])

payload = {
    "connection_location": "2",
    "connection_address": "192.168.43.66",
    "incoming_pubkey": keys["pubkey_hex_str"],
    "status": 'offline',  # other options are ‘away’, ‘busy’ or ‘offline’
}
byte_payload = bytes(json.dumps(payload), "utf-8")

req = urllib.request.Request(url=url, data=byte_payload, headers=header)
JSON_object = acc.query_server(req)

pprint.pprint(JSON_object)
