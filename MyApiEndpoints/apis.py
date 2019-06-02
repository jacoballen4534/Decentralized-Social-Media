import pprint
import urllib.request
import cherrypy
import exampleApiAccess.apiHelpers as acc
import json
import time
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader('static'), autoescape=True)


class Api(object):
    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET'])
    @cherrypy.tools.json_out()
    def ping(self):
        """Allow users to ping my server to check if it is online. Returns a JSON object containing an ok response and
         the current server time"""
        response = {
            'response': 'ok',
            'server_time': time.time(),
        }
        return response

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET'])
    @cherrypy.tools.json_out()
    def list_apis(self):
        """Returns a list of API's that have been implemented"""
        response = {
            "/ping": {
                "method": "GET",
                "purpose": """returns an 'ok' message and the current time. Used to check if my server is reachable"""
            },
            "/list_apis": {
                "method": "GET",
                "purpose": "Returns this list, showing what methods / endpoints have been implamented"
            }
        }
        return response


    @cherrypy.expose
    def rx_broadcast(self):
        print("broadcast triggered")
        received_data = json.loads(cherrypy.request.body.read().decode('utf-8'))

        message = received_data.get('message').encode('utf-8')
        print("Broadcast:")
        print(message)

        response = {'response': 'ok'}

        response = json.dumps(response)
        return response

    @cherrypy.expose
    def rx_privatemessage(self):
        print("privatemessage triggered")
        received_data = json.loads(cherrypy.request.body.read().decode('utf-8'))

        message = received_data.get('message').encode('utf-8')
        print("Broadcast:")
        print(message)

        response = {'response': 'ok'}

        response = json.dumps(response)
        return response
