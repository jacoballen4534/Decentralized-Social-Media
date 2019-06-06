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


class Updates(object):

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["POST"])
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def update_online_users(self):
        """This endpoint gets called by each client, from their browser. It will take the last """
        print("Updating browser user list")
        try:
            data = cherrypy.request.json
            print(data)
            received_data = json.loads(cherrypy.request.body.read().decode('utf-8'))
            username = cherrypy.session.get("username")
            api_key = cherrypy.session.get("api_key")
            pickled_keys = cherrypy.session.get("pickled_keys")
            keys = None
            if pickled_keys is not None:
                keys = pickle.loads(pickled_keys)
            debug_logger.debug("Request: " + str(received_data) + " from: " + str(username))
            report_status = loginServerApis.report(location="2", username=username, keys=keys, status="online", api_key=api_key)
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
        except Exception as e:
            print(e)


def poll_list_users():
    