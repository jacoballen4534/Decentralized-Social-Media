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
import db.messageStreamer as messageStreamer
from jinja2 import Environment, FileSystemLoader
import db.addData as database
import datetime
import pickle
from main import private_data_logger, info_logger, debug_logger

env = Environment(loader=FileSystemLoader('static'), autoescape=True)


class Api(object):
    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET'])
    @cherrypy.tools.json_out()
    def ping(self):
        """Allow users to ping my server to check if it is online. Returns a JSON object containing an ok response and
         the current server time"""
        response = {
            'response'   : 'ok',
            'server_time': time.time(),
        }
        return response

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET'])
    @cherrypy.tools.json_out()
    def list_apis(self):
        """Returns a list of API's that have been implemented"""
        response = {
            "/ping"        : {
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
                    'message': 'missing signature',
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

            message_bytes = message.encode('utf-8')
            received_from = received_data_body.get("loginserver_record").split(",")[0]
            info_logger.info("Received broadcast from " + str(received_from) + ": " + str(message))

            print("Received broadcast message: " + str(message))
            # Publish the new message to the cherrypy bus for adding to db and sending to al clients
            cherrypy.engine.publish("store_new_broadcast",
                                    {
                                        'loginserver_record': received_data_body.get("loginserver_record"),
                                        'message': message,
                                        'timestamp': received_data_body.get('sender_created_at')
                                    })
            #
            # database.add_public_broadcast(loginserver_record=received_data_body.get("loginserver_record"),
            #                               message=message, timestamp=received_data_body.get('sender_created_at'))
            response = {'response': 'ok'}
            return response
        except Exception:
            return {'response': 'error'}

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["POST"])
    @cherrypy.tools.json_out()
    def rx_privatemessage(self):
        print("privatemessage triggered")
        received_data = json.loads(cherrypy.request.body.read().decode('utf-8'))

        message = received_data.get('message').encode('utf-8')
        print("Broadcast:")
        print(message)

        response = {'response': 'ok'}

        response = json.dumps(response)
        return response

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["POST"])
    @cherrypy.tools.json_out()
    def report(self):
        """This endpoint gets called by each client, from their browser. It will be called every 20 seconds, telling
        the server to report them to the login server"""
        received_data = json.loads(cherrypy.request.body.read().decode('utf-8'))
        username = cherrypy.session.get("username")
        api_key = cherrypy.session.get("api_key")
        pickled_keys = cherrypy.session.get("pickled_keys")
        keys = None
        if pickled_keys is not None:
            keys = pickle.loads(pickled_keys)
        debug_logger.debug("Request: " + str(received_data) + " from: " + str(username))
        report_status = loginServerApis.report(location="2", username=username, keys=keys, status="online",
                                               api_key=api_key)
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
            'response'     : 'ok',
            'report_status': 'success' if report_status else 'failed',
            'user_id'      : username,
        }

    @cherrypy.expose
    def stream(self):
        """This is the endpoint my front end will subscribe to, to get new messages instantly"""
        channel = 'client_broadcast_update'

        doorman = messageStreamer.MessageStreamer(channel)
        cherrypy.response.headers["Content-Type"] = "text/event-stream; charset=utf-8"
        cherrypy.response.headers["Content-Type"] = "text/plain"
        # cherrypy.response.headers["Cache-Control"] = "no-cache"
        # cherrypy.response.headers["Connection"] = "keep-alive"

        def publish():
            for message in doorman.messages():
                try:
                    return message
                except GeneratorExit:
                    # cherrypy shuts down the generator when the client
                    # disconnects. Catch disconnect and unsubscribe to clean up
                    doorman.unsubscribe()
                    return
        return publish()

    stream._cp_config = {'response.stream': True}
# ___________________________Non exposed functions_________________________________________#


def send_broadcast(username, message, send_to_dict, keys, api_key=None, password=None):
    """Requires api_key or password. Takes a messages and a list of users to send it to.(Format of list_users).
    Needs the username and keys of the sender, to sign the message and create the loginserver_record"""
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

    for user in send_to_dict:
        broadcast_thread = threading.Thread(target=individual_thread_broadcast, args=([user, byte_payload, header,
                                                                                       api_key, password, username]))
        broadcast_thread.start()
    return True


# threading.Thread(target=fun1, args=(12,10))


def individual_thread_broadcast(user, byte_payload, header, api_key=None, password=None, username=None):
    broadcast_url = "http://" + user['connection_address'] + "/api/rx_broadcast"
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
    pprint.pprint("Resuly of request to " + broadcast_url + ": " + json_object['response'])




# # yield 'retry: 1000\n\n'
#         def generator():
#             id = 0
#             while True:
#                 id = id + 1
#                 yield 'id: ' + str(id) + '\n' \
#                                          'event: new_broadcast\n' \
#                                          'data: There is a new broadcast\n\n' \
#                                          'data: message number will be on 3rd line\n' \
#                                          'data: Message number: ' + str(id) + '\n\n'
#                 time.sleep(1)
#
#         return generator()
#
#     update_public_broadcasts._cp_config = {'response.stream': True}