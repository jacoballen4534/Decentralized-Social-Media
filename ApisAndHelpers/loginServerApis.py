import urllib.request
import urllib.error
import json
import pprint
import logging
import ApisAndHelpers.requests as request_helper
import ApisAndHelpers.crypto as crypto
import db.addData as database


def ping(username=None, password=None, keys=None, api_key=None):
    """This method has three purposes depending on the parameters passed in.
    1. No username will simply check if the server is online.
    2. Username and api key, will check api_key status. And return X_signature
    3. Username and password with no key, will authenticate the credentials with HTTP Basic.
    4. Username, Password and keys, will authenticate the private key matches the registered public key"""

    ping_url = "http://cs302.kiwi.land/api/ping"
    try:
        if username is None:  # Check if the server is online
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
        elif api_key is not None:  # Check api_key
            print("Checking if the provided api_key is valid for that username and password")
            header = request_helper.create_api_header(username, api_key)
            authentication_request = urllib.request.Request(url=ping_url, headers=header)
            authentication_object = request_helper.query_server(authentication_request)
            if authentication_object['response'] == 'ok' and authentication_object['authentication'] == 'api-key':
                print("This api key is valid.")
                return True
            else:
                print("It doesnt look like those are valid credentials")
                logging.debug("invalid credentials: " + str(username) + str(password))
                return False
        elif password is not None and keys is None:  # This means check HTTPBasic
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
        elif password is not None and keys is not None:
            print("Checking if the provided key is valid")
            header = request_helper.create_basic_header(username, password)
            signature_hex_str = crypto.sign_message(keys["public_key_hex_string"], private_key=keys['private_key'])
            payload = {
                "pubkey"   : keys["public_key_hex_string"],
                "signature": signature_hex_str
            }
            byte_payload = bytes(json.dumps(payload), "utf-8")

            signature_request = urllib.request.Request(url=ping_url, data=byte_payload, headers=header)
            verify_signature_object = request_helper.query_server(signature_request)
            if verify_signature_object['response'] == 'ok' and verify_signature_object['signature'] == 'ok':
                return True
            else:
                return False
        else:
            return False
    except TypeError:
        return False


def load_new_apikey(username, password=None, api_key=None):
    """Get a new api key from the login server for the given user.
    If an api key is provided, it will use that instead of httpBasic"""
    url = "http://cs302.kiwi.land/api/load_new_apikey"
    if api_key is not None:
        header = request_helper.create_api_header(x_username=username, api_key=api_key)
    elif password is not None:
        header = request_helper.create_basic_header(username, password)
    else:
        return None

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


def report(location, username, keys, status="online", api_key=None, password=None):
    import socket
    import main
    report_url = "http://cs302.kiwi.land/api/report"

    global ip
    ip = main.LISTEN_IP
    port = main.LISTEN_PORT
    location = main.LOCATION
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

    if api_key is not None:
        header = request_helper.create_api_header(x_username=username, api_key=api_key)
    elif password is not None:
        header = request_helper.create_basic_header(username=username, password=password)
    else:
        return False

    payload = {
        "connection_location": location,
        "connection_address" : connection_address,
        "incoming_pubkey"    : keys["public_key_hex_string"],
        "status"             : status,
    }
    byte_payload = bytes(json.dumps(payload), "utf-8")

    req = urllib.request.Request(url=report_url, data=byte_payload, headers=header)
    json_object = request_helper.query_server(req)
    if json_object['response'] == 'ok':
        pprint.pprint(json_object)
        return True
    else:
        return False


def list_users(username, api_key=None, password=None):
    """takes a username and password to use as authorisation to get all online users. Returns this in a dictionary"""
    list_users_url = "http://cs302.kiwi.land/api/list_users"
    try:
        if api_key is not None:
            print("listing users with api_key")
            header = request_helper.create_api_header(x_username=username, api_key=api_key)
        elif password is not None:
            print("listing users with HTTP Basic")
            header = request_helper.create_basic_header(username=username, password=password)
        else:
            return {}

        req = urllib.request.Request(url=list_users_url, headers=header)
        list_users_object = request_helper.query_server(req)
        if list_users_object['response'] == 'ok':
            users = list_users_object['users']
            # pprint.pprint(list_users_object)
            for user in users:
                database.update_user_list(user)

            return users
        else:
            return {}
    except Exception as e:
        print(e)
        return {}


def add_pub_key(keys, username, api_key=None, password=None):
    """Takes an object with the new keys along with the username and password for the account.
    Will add the given public key to the users account. Returns True for successful add, False otherwise"""

    add_pup_key_url = "http://cs302.kiwi.land/api/add_pubkey"

    if api_key is not None:
        print("listing users with api_key")
        header = request_helper.create_api_header(x_username=username, api_key=api_key)
    elif password is not None:
        print("listing users with HTTP Basic")
        header = request_helper.create_basic_header(username=username, password=password)
    else:
        return False

    signature_hex_str = crypto.sign_message(keys["public_key_hex_string"] + username, keys['private_key'])

    payload = {
        "pubkey"   : keys["public_key_hex_string"],
        "username" : username,
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


def get_private_data(username, encryption_key, api_key=None, password=None):
    """Retrieves the private data associated with the given username and password.
    Will try to decrypt it with the provided encryption key"""

    url = "http://cs302.kiwi.land/api/get_privatedata"

    if api_key is not None:
        print("getting private data with api_key")
        header = request_helper.create_api_header(x_username=username, api_key=api_key)
    elif password is not None:
        print("getting private data with HTTP Basic")
        header = request_helper.create_basic_header(username=username, password=password)
    else:
        return False, {}

    req = urllib.request.Request(url=url, headers=header)
    private_data_object = request_helper.query_server(req)

    if private_data_object['response'] != 'ok' or 'privatedata' not in private_data_object:
        return False, {}

    encrypted_private_data_base64_string = private_data_object['privatedata']
    print("Encrypted private data retrieved:")
    pprint.pprint(encrypted_private_data_base64_string)
    # _________________________ Decrypt the private data _______________________________________
    status, decrypted_private_data_dict = crypto.decrypt_private_data(encrypted_private_data_base64_string,
                                                                      encryption_key)
    if not status:
        return False, {}
    if 'prikeys' not in decrypted_private_data_dict:
        decrypted_private_data_dict['prikeys'] = [""]
    return True, decrypted_private_data_dict


def list_apis():
    """Query the login server to find what api's have been implemented Prints this out"""
    url = "http://cs302.kiwi.land/api/list_apis"
    request = urllib.request.Request(url=url)
    json_object = request_helper.query_server(request)
    if json_object['response'] == 'ok':
        pprint.pprint(json_object)


def get_loginserver_record(username, api_key=None, password=None):
    """Request the users login server record, to be used as authentication for some future requests"""
    url = "http://cs302.kiwi.land/api/get_loginserver_record"

    if api_key is not None:
        print("getting record with api_key")
        header = request_helper.create_api_header(x_username=username, api_key=api_key)
    elif password is not None:
        print("getting record with HTTP Basic")
        header = request_helper.create_basic_header(username=username, password=password)
    else:
        return False, ""

    request = urllib.request.Request(url=url, headers=header)
    json_object = request_helper.query_server(request)
    if json_object['response'] == 'ok' and 'loginserver_record' in json_object:
        loginserver_record = json_object['loginserver_record']
        pprint.pprint(loginserver_record)
        return True, loginserver_record
    else:
        return False, ""


def check_pubkey(username, public_key_kex_string_to_check, api_key=None, password=None):
    """"Will retreive the loginserver record, from the login server, associated with the public key provided
    Public key is in string(256-bit Ed25519 hex encoded format"""
    check_pup_key_url = "http://cs302.kiwi.land/api/check_pubkey"

    if api_key is not None:
        print("getting record with api_key")
        header = request_helper.create_api_header(x_username=username, api_key=api_key)
    elif password is not None:
        print("getting record with HTTP Basic")
        header = request_helper.create_basic_header(username=username, password=password)
    else:
        return False, ""

    check_pup_key_url = str(check_pup_key_url) + "?pubkey=" + str(public_key_kex_string_to_check)
    # check_pup_key_url = str(check_pup_key_url) + "?pubkey=" +
    # str("b9eba910b59549774d55d3ce49a7b4d46ab5e225cdcf2ac388cf356b5928b6bc")#someones pubkey
    request = urllib.request.Request(url=check_pup_key_url, headers=header)
    json_object = request_helper.query_server(request)
    if json_object['response'] == 'ok' and 'loginserver_record' in json_object:
        loginserver_record = json_object['loginserver_record']
        pprint.pprint(loginserver_record)
        return True, loginserver_record
    else:
        return False, ""


def add_private_data(username, plain_text_private_data_dictonary, keys, encryption_key, api_key=None, password=None):
    """Takes the new private data to be added (in plain text dictionary form. Will encrypt with the encryption key
    provided. The resulting secret message will then be signed and stored on the central server."""
    import time
    from base64 import b64encode
    import nacl.exceptions

    add_privatedata_url = "http://cs302.kiwi.land/api/add_privatedata"
    try:
        if api_key is not None:
            print("getting private data with api_key")
            header = request_helper.create_api_header(x_username=username, api_key=api_key)
        elif password is not None:
            print("getting private data with HTTP Basic")
            header = request_helper.create_basic_header(username=username, password=password)
        else:
            return False

        private_data_plain_text_string = json.dumps(plain_text_private_data_dictonary)
        private_data_plain_text_bytes = bytes(private_data_plain_text_string, "utf-8")

        status, encrypted_message = crypto.encrypt_private_data(private_data_plain_text_bytes=private_data_plain_text_bytes
                                                                , encryption_key=encryption_key)
        if not status:
            return False

        status, loginserver_record = get_loginserver_record(username=username, password=password,
                                                            api_key=api_key)  # Only one of password and api_key required
        if not status:
            return False

        current_time = str(time.time())

        # Encode the encrypted message object into base64 bytes.
        encrypted_message_base64_bytes = b64encode(encrypted_message)
        # Convert the base64 bytes to string to be added to the payload and added to the signature.
        base64_string = encrypted_message_base64_bytes.decode('utf-8')
        signature_hex_str = crypto.sign_message(base64_string + loginserver_record + current_time, keys['private_key'])

        payload = {
            "privatedata": base64_string,
            "loginserver_record": loginserver_record,
            "client_saved_at": current_time,
            "signature": signature_hex_str
        }

        byte_payload = bytes(json.dumps(payload), "utf-8")

        add_privatedata_request = urllib.request.Request(url=add_privatedata_url, data=byte_payload, headers=header)

        json_object = request_helper.query_server(add_privatedata_request)
        if json_object['response'] == 'ok':
            print("\n\nSecessfully added encrypted private data")
            pprint.pprint(json_object)
            return True
        else:
            return False

    except (TypeError, nacl.exceptions.CryptoError):
        print("Could not add new private data")

    return False
