import urllib.request
import urllib.error
import json
import pprint
import logging
import ApisAndHelpers.requests as request_helper
import ApisAndHelpers.crypto as crypto


def ping(username=None, password=None, keys=None, api_key=None):
    """This method has three purposes depending on the parameters passed in.
    1. No parameters will simply check if the server is online.
    2. Username and password only, will authenticate the credentials with HTTP Basic.
    3. Username, Password and keys, will authenticate the private key matches the registered public key"""

    ping_url = "http://cs302.kiwi.land/api/ping"
    try:
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
        elif username is not None and password is not None and keys is None and api_key is None:  # This means check HTTPBasic
            print("Checking if the provided username and password is valid")
            header = request_helper.create_basic_header(username, password)
            authentication_request = urllib.request.Request(url=ping_url, headers=header)
            authentication_object = request_helper.query_server(authentication_request)

            if authentication_object['response'] == 'ok' and authentication_object['authentication'] == 'basic':
                print("These credentials are valid.")
                return True
            else:
                print("It doesnt look like those are valid credentials")
                logging.debug("invalid credentials: " + str(username) + str(password))
                return False
        elif username is not None and password is not None and keys is None and api_key is not None:  # Check api_key
            print("Checking if the provided api_key is valid for that username and password")
            header = request_helper.create_api_header(username, api_key, password)
            authentication_request = urllib.request.Request(url=ping_url, headers=header)
            authentication_object, response_header = request_helper.query_server(authentication_request, headers=True)
            if authentication_object['response'] == 'ok' and authentication_object['authentication'] == 'api-key':
                print("This api key is valid.")
                x_signature = response_header.get('X-Signature')
                if x_signature is not None:
                    return True, x_signature
                return True
            else:
                print("It doesnt look like those are valid credentials")
                logging.debug("invalid credentials: " + str(username) + str(password))
                return False

        elif username is not None and password is not None and keys is not None:
            print("Checking if the provided key is valid")
            header = request_helper.create_basic_header(username, password)
            signature_hex_str = crypto.sign_message(keys["public_key_hex_string"], private_key=keys['private_key'])
            payload = {
                "pubkey": keys["public_key_hex_string"],
                "signature": signature_hex_str
            }
            byte_payload = bytes(json.dumps(payload), "utf-8")

            signature_request = urllib.request.Request(url=ping_url, data=byte_payload, headers=header)
            verify_signature_object = request_helper.query_server(signature_request)
            if verify_signature_object['response'] == 'ok' and verify_signature_object['signature'] == 'ok':
                return True
            else:
                raise False
    except TypeError:
        return False


def load_new_apikey(username, password):
    """Get a new api key from the login server for the given user."""
    url = "http://cs302.kiwi.land/api/load_new_apikey"
    header = request_helper.create_basic_header(username, password)
    request = urllib.request.Request(url=url, headers=header)
    json_object = request_helper.query_server(request)
    if json_object['response'] == 'ok':
        pprint.pprint(json_object)
        return json_object['api_key']
    else:
        return None


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

    header = request_helper.create_basic_header(username, password)

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
    #TODO Setup thread to keep reporting the users


def list_users(username, password):
    """takes a username and password to use as authorisation to get all online users. Returns this in a dictionary"""
    list_users_url = "http://cs302.kiwi.land/api/list_users"
    header = request_helper.create_basic_header(username, password)

    req = urllib.request.Request(url=list_users_url, headers=header)
    list_users_object = request_helper.query_server(req)
    if list_users_object['response'] == 'ok':
        pprint.pprint(list_users_object)
        return list_users_object['users']
    else:
        list_users_object['users'] = [{}]
        return list_users_object


def add_pub_key(keys, username, password):
    """Takes an object with the new keys along with the username and password for the account.
    Will add the given public key to the users account. Returns True for successful add, False otherwise"""

    add_pup_key_url = "http://cs302.kiwi.land/api/add_pubkey"
    header = request_helper.create_basic_header(username, password)
    signature_hex_str = crypto.sign_message(keys["public_key_hex_string"] + username, keys['private_key'])

    payload = {
        "pubkey": keys["public_key_hex_string"],
        "username": username,
        "signature": signature_hex_str
    }

    byte_payload = bytes(json.dumps(payload), "utf-8")

    req = urllib.request.Request(url=add_pup_key_url, data=byte_payload, headers=header)
    new_pub_key_object = request_helper.query_server(req)
    if new_pub_key_object['response'] == 'ok':
        print("Successfully added a new pubkey")
        pprint.pprint(new_pub_key_object)
        return True
    else:
        return False


def get_private_data(username, password, encryption_key):
    """Retrieves the private data associated with the given username and password.
    Will try to decrypt it with the provided encryption key"""

    url = "http://cs302.kiwi.land/api/get_privatedata"
    header = request_helper.create_basic_header(username, password)
    req = urllib.request.Request(url=url, headers=header)
    private_data_object = request_helper.query_server(req)

    if private_data_object['response'] != 'ok' or 'privatedata' not in private_data_object:
        return False, {}

    encrypted_private_data_base64_string = private_data_object['privatedata']
    print("Encrypted private data retrieved:")
    pprint.pprint(encrypted_private_data_base64_string)
    # _________________________ Decrypt the private data _______________________________________
    status, decrypted_private_data_dict = crypto.decrypt_private_data(encrypted_private_data_base64_string, encryption_key)
    if not status:
        return False, {}
    if 'prikeys' not in decrypted_private_data_dict:
        decrypted_private_data_dict['prikeys'] = [""]
    return True, decrypted_private_data_dict
