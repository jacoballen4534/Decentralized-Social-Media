import urllib.request
import json
import pprint
import time
import nacl.encoding
import nacl.signing
import nacl.utils
import accountParameters as acc
import loginServerPubKey

broadcast_url = "http://cs302.kiwi.land/api/rx_privatemessage"
header = acc.create_header()
keys = acc.get_keys()

loginserver_record = acc.get_server_record()

target_pubkey_json = loginServerPubKey.login_server_pub_key()
if 'pubkey' in target_pubkey_json:
    target_pubkey_str = target_pubkey_json['pubkey']
else:
    exit(1)

target_username = "admin"  # get from loginServerRecord of target
plain_text_message = chr(127829) + "@ 🅱att"

sender_created_at = str(time.time())

#publickey_hex contains the target publickey
#using the nacl.encoding.HexEncoder format
target_publickey_bytes = str.encode(target_pubkey_str)  # convert target_pubkey to bytes

verifykey = nacl.signing.VerifyKey(target_publickey_bytes, encoder=nacl.encoding.HexEncoder)
target_publickey_curve = verifykey.to_curve25519_public_key()
sealed_box = nacl.public.SealedBox(target_publickey_curve)
encrypted = sealed_box.encrypt(str.encode(plain_text_message), encoder=nacl.encoding.HexEncoder)
message = encrypted.decode('utf-8')  # This is the message to send (string)


signature_hex_str = acc.sign_message(loginserver_record + target_pubkey_str +
                                     target_username + message + sender_created_at)

payload = {
    'loginserver_record': loginserver_record,
    'target_pubkey': target_pubkey_str,
    'target_username': target_username,
    "encrypted_message": message,
    "sender_created_at": sender_created_at,
    "signature": signature_hex_str
}

byte_payload = bytes(json.dumps(payload), "utf-8")
# pprint.pprint(payload)

req = urllib.request.Request(url=broadcast_url, data=byte_payload, headers=header)
JSON_object = acc.query_server(req)

pprint.pprint(JSON_object)
