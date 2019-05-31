import pprint
import urllib.request
import json
import base64

import nacl.encoding
import nacl.signing
import nacl.utils


username = "jall229"


def get_keys():
    hex_key = b'bae8e8311801aabe5d4eb4c85f3ba53a54c7a2fffbc561e59a6ff53765dfe138'
    signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)
    pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')
    keys = {"signing_key": signing_key,
            "pubkey_hex_str": pubkey_hex_str}
    return keys


def create_header():
    password = "jacoballen4534_205023320"
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }
    return headers


def get_server_record():
    server_record_url = "http://cs302.kiwi.land/api/get_loginserver_record"
    header = create_header()
    request = urllib.request.Request(url=server_record_url, headers=header)
    JSON_object = query_server(request)
    loginserver_record = JSON_object['loginserver_record']
    return loginserver_record


def sign_message(message):
    keys = get_keys()
    signature_bytes = bytes(message, encoding='utf-8')
    signed = keys["signing_key"].sign(signature_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')
    return signature_hex_str


def query_server(request):
    response = urllib.request.urlopen(request)

    data = response.read()  # read the received bytes
    encoding1 = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
    response.close()

    JSON_object = json.loads(data.decode(encoding1))
    return JSON_object