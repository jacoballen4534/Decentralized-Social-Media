import urllib.request
import urllib.error
import json
import pprint
import logging
import ApisAndHelpers.requests as request_helper
import ApisAndHelpers.crypto as crypto


def ping(username=None, password=None, keys=None):
    """This method has three purposes depending on the parameters passed in.
    1. No parameters will simply check if the server is online.
    2. Username and password only, will authenticate the credentials with HTTP Basic.
    3. Username, Password and keys, will authenticate the private key matches the registered public key"""

    ping_url = "http://cs302.kiwi.land/api/ping"
    if username is None or password is None:
        print("Checking if the server is online")
        status_request = urllib.request.Request(url=ping_url)
        json_object = request_helper.query_server(status_request)
        if json_object['response'] == 'ok':
            print("Server is online and reachable.")
            logging.debug("Server online")
            return True
        else:
            logging.debug("Server offline")
            print("Sorry, it appears the server is not reachable at this time")
            return False
    elif username is not None and password is not None and keys is None:  # This means check HTTPBasic
        print("Checking if the provided username and password is valid")
        header = request_helper.create_header(username, password)
        authentication_request = urllib.request.Request(url=ping_url, headers=header)
        authentication_object = request_helper.query_server(authentication_request)

        if authentication_object['response'] == 'ok' and authentication_object['authentication'] == 'basic':
            print("These credentials are valid.")
            return True
        else:
            print("It doesnt look like those are valid credentials")
            logging.debug("invalid credentials: " + str(username) + str(password))
            return False
    elif username is not None and password is not None and keys is not None:
        print("Checking if the provided key is valid")
        header = request_helper.create_header(username, password)
        signature_hex_str = crypto.sign_message(keys["pubkey_hex_str"], private_key=keys['private_key'])
        payload = {
            "pubkey": keys["pubkey_hex_str"],
            "signature": signature_hex_str
        }
        byte_payload = bytes(json.dumps(payload), "utf-8")

        signature_request = urllib.request.Request(url=ping_url, data=byte_payload, headers=header)
        verify_signature_object = request_helper.query_server(signature_request)
        if verify_signature_object['response'] == 'ok' and verify_signature_object['signature'] == 'ok':
            return True
        else:
            raise False


def load_new_apikey(username, password):
    """Get a new api key from the login server for the given user."""
    url = "http://cs302.kiwi.land/api/load_new_apikey"
    header = request_helper.create_header(username, password)
    request = urllib.request.Request(url=url, headers=header)
    json_object = request_helper.query_server(request)
    if json_object['response'] == 'ok':
        pprint.pprint(json_object)
        return json_object['api_key']


def loginserver_pubkey():
    """Retreive the login server's public key. Returns the public_key hex string"""
    url = "http://cs302.kiwi.land/api/loginserver_pubkey"
    request = urllib.request.Request(url=url)
    json_object = request_helper.query_server(request)
    if json_object['response'] == 'ok':
        pprint.pprint(json_object)
        return json_object['pubkey']


def report(location, username, password, keys, status="online"):
    import socket
    import main
    report_url = "http://cs302.kiwi.land/api/report"

    global ip
    ip = main.LISTEN_IP
    port = main.LISTEN_PORT
    if location == "0" or location == "1":  # If the user is at uni, use local ip
        ip = socket.gethostbyname(socket.gethostname())
    else:  # Otherwise, try to get public ip of server
        try:
            ip_url = "https://api.ipify.org/?format=json"
            ip_request = urllib.request.Request(url=ip_url)
            ip_object = request_helper.query_server(ip_request)
            if 'ip' in ip_object:
                ip = ip_object['ip']
        except urllib.error.URLError as e:
            print(e)
    connection_address = str(ip) + ":" + str(port)
    print(connection_address)

    header = request_helper.create_header(username, password)

    payload = {
        "connection_location": location,
        "connection_address": connection_address,
        "incoming_pubkey": keys["public_key_hex_string"],
        "status": status,
    }
    byte_payload = bytes(json.dumps(payload), "utf-8")

    req = urllib.request.Request(url=report_url, data=byte_payload, headers=header)
    json_object = request_helper.query_server(req)
    if json_object['response'] == 'ok':
        pprint.pprint(json_object)
        return True
    else:
        return False
    #TODO Setup thread to keep reporting
