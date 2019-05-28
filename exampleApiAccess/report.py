import urllib.request
import json
import pprint
import apiHelpers as acc


hex_key = b'bae8e8311801aabe5d4eb4c85f3ba53a54c7a2fffbc561e59a6ff53765dfe138'

url = "http://cs302.kiwi.land/api/report"
header = acc.create_header("jall229", "jacoballen4534_205023320")
keys = acc.get_keys(hex_key)

signature_hex_str = acc.sign_message(keys["pubkey_hex_str"])

payload = {
    "connection_location": "2",
    "connection_address": "192.168.43.66",
    "incoming_pubkey": keys["pubkey_hex_str"],
}
byte_payload = bytes(json.dumps(payload), "utf-8")

req = urllib.request.Request(url=url, data=byte_payload, headers=header)
JSON_object = acc.query_server(req)

pprint.pprint(JSON_object)
