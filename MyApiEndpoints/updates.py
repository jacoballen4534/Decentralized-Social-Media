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
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader('static'), autoescape=True)


class Updates(object):

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["POST"])
    # @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def update_online_users(self):
        """This endpoint gets called by each client, from their browser. It will get a new list on online users"""
        try:
            data = cherrypy.request.json
            feed_template = env.get_template('/html/online_user_module.html')

            username = cherrypy.session.get('username')
            api_key = cherrypy.session.get('api_key')

            # If they shouldnt be here. Kick them back to login.
            if username is None or api_key is None:
                raise cherrypy.HTTPRedirect('/')
            print("Request: " + str(data) + " from: " + str(username))

            online_users = loginServerApis.list_users(username=username, api_key=api_key)
            temp = json.dumps(feed_template.render(username=username, users=online_users))
            return temp
        except Exception as e:
            print(e)
