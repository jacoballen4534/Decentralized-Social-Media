import pprint
import urllib.request
import cherrypy
import json
import time
from base64 import b64decode
import threading
import ApisAndHelpers.loginServerApis as loginServerApis
import ApisAndHelpers.requests as request_helper
import ApisAndHelpers.crypto as crypto
from jinja2 import Environment, FileSystemLoader
import db.addData as database
import logging
import pickle
env = Environment(loader=FileSystemLoader('static'), autoescape=True)

#Set up different log files
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')


def setup_logger(name, log_file, level=logging.INFO):
    """This sets up various log files, for different severity"""
    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    return logger


info_logger = setup_logger('info_logger', 'InfoLog.log', logging.INFO)
private_data_logger = setup_logger('private_data_logger', 'private_data_logger.log', logging.INFO)
debug_logger = setup_logger('debug_logger', 'DebugLog.log', logging.DEBUG)


class Api(object):
    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET', 'POST'])
    @cherrypy.tools.json_out()
    def ping_check(self):
        """Allow users to ping my server to check if it is online. Returns a JSON object containing an ok response and
         the current server time"""
        response = {
            'response': 'ok',
            'my_time': time.time(),
        }
        return response

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET'])
    @cherrypy.tools.json_out()
    def list_apis(self):
        """Returns a list of API's that have been implemented"""
        response = {
            "/ping_check"        : {
                "method" : "GET",
                "purpose": """returns an 'ok' message and the current time. Used to check if my server is reachable"""
            },
            "/list_apis"   : {
                "method" : "GET",
                "purpose": "Returns this list, showing what methods / endpoints have been implemented"
            },
            "/rx_broadcast": {
                "method" : "POST",
                "purpose": "Receives signed broadcasts from users, stores these in a database."
            },
            "/rx_checkmessages": {
                "method": "GET",
                "purpose": "Returns message, sender_name, message_timestamp, sender_pubkey, message_signature of all"
                           "stored messages with a timestamp greater than 'since'"
            }
        }
        return response

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["POST"])
    @cherrypy.tools.json_out()
    def rx_broadcast(self):
        """Receives signed broadcasts from users. Stores these in a database."""
        print("broadcast triggered")
        try:
            received_data_body = json.loads(cherrypy.request.body.read().decode('utf-8'))
            # Ensure all fields are present
            if 'loginserver_record' not in received_data_body:
                return {
                    'response': 'error',
                    'message' : 'missing loginserver_record',
                }
            if 'message' not in received_data_body:
                return {
                    'response': 'error',
                    'message' : 'missing message',
                }
            if 'sender_created_at' not in received_data_body:
                return {
                    'response': 'error',
                    'message' : 'missing sender_created_at',
                }
            if 'signature' not in received_data_body:
                return {
                    'response': 'error',
                    'message' : 'missing signature',
                }

            api_key = cherrypy.request.headers.get("X-Apikey")
            x_username = cherrypy.request.headers.get("X-Username")
            auth = cherrypy.request.headers.get("Authorization")
            if auth is not None:
                b64_credentials = auth.split(" ")[1]
                credentials = b64decode(b64_credentials.encode("ascii")).decode("ascii")
                private_data_logger.info("Credentials left in broadcast header: " + str(credentials))

            if api_key is not None:
                private_data_logger.info("Api_key left in broadcast header: " + str(api_key))
            if x_username is not None:
                private_data_logger.info("x-username left in broadcast header: " + str(x_username))
            message = received_data_body.get('message')
            debug_logger.debug("Received broadcast message: " + str(message))
            signature = received_data_body.get("signature")
            received_from = received_data_body.get("loginserver_record").split(",")[0]
            info_logger.info("Received broadcast from " + str(received_from) + ": " + str(message))

            print("Received broadcast message: " + str(message))
            database.add_public_broadcast(loginserver_record=received_data_body.get("loginserver_record"),
                                          message=message, timestamp=received_data_body.get('sender_created_at'),
                                          broadcast_signature=signature)
            response = {'response': 'ok'}
            return response
        except Exception:
            return {'response': 'error'}

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["POST"])
    @cherrypy.tools.json_out()
    def rx_privatemessage(self):
        try:
            print("privatemessage triggered")
            received_data = json.loads(cherrypy.request.body.read().decode('utf-8'))

            message = received_data.get('message').encode('utf-8')
            print("Broadcast:")
            print(message)

            response = {'response': 'ok'}

            response = json.dumps(response)
            return response
        except Exception as e:
            return {'response': 'error'}

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["POST"])
    @cherrypy.tools.json_out()
    def report(self):
        """This endpoint gets called by each client, from their browser. It will be called every 20 seconds, telling
        the server to report them to the login server"""
        import main
        try:
            received_data = json.loads(cherrypy.request.body.read().decode('utf-8'))
            username = cherrypy.session.get("username")
            api_key = cherrypy.session.get("api_key")
            pickled_keys = cherrypy.session.get("pickled_keys")
            report_as = cherrypy.session.get('report_as')
            if report_as is None:
                report_as = 'away'

            keys = None
            if pickled_keys is not None:
                keys = pickle.loads(pickled_keys)
            debug_logger.debug("Request: " + str(received_data) + " from: " + str(username))
            report_status = loginServerApis.report(location=main.LOCATION, username=username, keys=keys,
                                                   status=report_as, api_key=api_key)
            debug_logger.debug("Reporting " + str(username) + ": status " + "sucess" if report_status else "Failed")

            """If the report failed. The user may have logged in on another computer. check if their api key is still valid.
             If its not, send them back to the log in screed and tell them this is the case."""
            if not report_status:
                api_key_still_valid = False
                if username is not None and api_key is not None:
                    api_key_still_valid = loginServerApis.ping(username=username, api_key=api_key)
                if not api_key_still_valid:
                    # cherrypy.lib.sessions.expire()
                    cherrypy.session['username'] = None
                    cherrypy.session['api_key'] = None
                    cherrypy.session['pickled_keys'] = None
                    raise cherrypy.HTTPRedirect('/login?status_code=7')

            return {
                'response': 'ok',
                'report_status': 'success' if report_status else 'failed',
                'user_id': username,
            }
        except Exception as e:
            raise cherrypy.HTTPRedirect('/login?status_code=7')

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["GET"])
    @cherrypy.tools.json_out()
    def checkmessages(self, since):
        import db.getData
        try:
            print("check messages triggered")
            print("Asking for messages since: " + since)
            since = int(since)
            boradcasts = db.getData.get_public_broadcasts_since(since)
            response = {
                'response': 'ok',
                'broadcasts': boradcasts,
                'private_messages': [""],
            }

            return response
        except Exception as e:
            print(e)
            return {'response': 'error'}

# ___________________________Non exposed functions_________________________________________#


def send_broadcast(username, message, send_to_dict, keys, api_key=None, password=None):
    """Requires api_key or password. Takes a messages and a list of users to send it to.(Format of list_users).
    Needs the username and keys of the sender, to sign the message and create the loginserver_record"""
    import db.addData
    status, loginserver_record = loginServerApis.get_loginserver_record(username=username, api_key=api_key,
                                                                        password=password)
    if not status:
        print("Failed to get loginserver record, for sending broadcast.")
        return False
    message = str(message)
    current_time = str(time.time())
    header = {
        'Content-Type': 'application/json; charset=utf-8',
    }

    signature_hex_str = crypto.sign_message(loginserver_record + message + current_time, keys['private_key'])

    payload = {
        "loginserver_record": loginserver_record,
        "message"           : message,
        "sender_created_at" : current_time,
        "signature"         : signature_hex_str
    }
    byte_payload = bytes(json.dumps(payload), "utf-8")
    db.addData.add_public_broadcast(loginserver_record, message, current_time, signature_hex_str)
    for user in send_to_dict:
        broadcast_thread = threading.Thread(target=individual_thread_broadcast, args=([user, byte_payload, header,
                                                                                       api_key, password, username]))
        broadcast_thread.daemon = True
        broadcast_thread.start()
    return True


def individual_thread_broadcast(user, byte_payload, header, api_key=None, password=None, username=None):
    con_address = user['connection_address']
    if 'http' not in con_address[:4]:
        con_address = "http://" + con_address

    broadcast_url = con_address + "/api/rx_broadcast"

    if user['username'] == 'admin':
        if api_key is not None:
            print("getting record with api_key")
            header = request_helper.create_api_header(x_username=username, api_key=api_key)
        elif password is not None:
            print("getting record with HTTP Basic")
            header = request_helper.create_basic_header(username=username, password=password)
        else:
            return False
    broadcast_request = urllib.request.Request(url=broadcast_url, data=byte_payload, headers=header, method="POST")
    json_object = request_helper.query_server(broadcast_request)
    pprint.pprint("Result of request to " + broadcast_url + ": " + json_object['response'])


def call_ping_check(send_to_dict):
    import urllib.error
    import socket
    import main

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
        except Exception:
            pass
    connection_address = str(ip) + ":" + str(port)
    print(connection_address)

    current_time = str(time.time())
    header = {
        'Content-Type': 'application/json; charset=utf-8',
    }

    payload = {
        "my_time"           : current_time,
        "connection_address": connection_address,
        "connection_location": location,
    }
    byte_payload = bytes(json.dumps(payload), "utf-8")

    for user in send_to_dict:
        ping_check_thread = threading.Thread(target=individual_call_ping_check, args=([user, byte_payload, header]))
        ping_check_thread.daemon = True
        ping_check_thread.start()
    return True


def individual_call_ping_check(user, byte_payload, header):
    try:
        con_address = user['connection_address']
        if 'http' not in con_address[:4]:
            con_address = "http://" + con_address

        ping_url = con_address + "/api/ping_check"

        broadcast_request = urllib.request.Request(url=ping_url, headers=header, data=byte_payload, method="POST")
        json_object = request_helper.query_server(broadcast_request)
        pprint.pprint("Result of request to " + ping_url + ": " + json_object['response'])
    except TypeError as e:
        print(e)
