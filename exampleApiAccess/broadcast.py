import urllib.request
import json
import pprint
import time
import apiHelpers as acc

broadcast_url = "47.72.180.5:1234/api/rx_broadcast"

header = acc.create_header()
keys = acc.get_keys()

loginserver_record = acc.get_server_record()

message = "Ok 6 days ago I guess"
current_time = str(time.time())

signature_hex_str = acc.sign_message(loginserver_record + message + current_time)

payload = {
    "loginserver_record": loginserver_record,
    "message": message,
    "sender_created_at": current_time,
    "signature": signature_hex_str
}

byte_payload = bytes(json.dumps(payload), "utf-8")
pprint.pprint(payload)

req = urllib.request.Request(url=broadcast_url, data=byte_payload, headers=header)
JSON_object = acc.query_server(req)

pprint.pprint(JSON_object)
