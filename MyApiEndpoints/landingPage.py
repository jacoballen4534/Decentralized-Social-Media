import pprint
import urllib.request
import cherrypy
import pickle
import json
import MyApiEndpoints.login
import main
import time
import ApisAndHelpers.loginServerApis as loginApi
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader('static'), autoescape=True)


class LandingPage:
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        error_template = env.get_template('/html/404Error.html')
        cherrypy.response.status = 404
        return error_template.render()

    @cherrypy.expose
    def index(self, *args, **kwargs):
        """The landing page for my sight. If the user is already logged in, take them to their home page,
        otherwise, take them to the login page."""

        username = cherrypy.session.get('username')
        api_key = cherrypy.session.get('api_key')
        pickled_keys = cherrypy.session.get("pickled_keys")
        cherrypy.session['last_activity_time'] = str(time.time())
        api_key_still_valid = False
        try:
            keys = pickle.loads(pickled_keys)
        except Exception:
            raise cherrypy.HTTPRedirect('/login')  # This will take the user to their news feed

        if username is not None and api_key is not None:
            api_key_still_valid = loginApi.ping(username=username, api_key=api_key)

        #TODO: Note that they dont need an encryption key, as they can manualy enter priv key. Will not be able to access private data tho
        if username is not None and keys is not None and api_key is not None and api_key_still_valid:
            loginApi.report(location=main.LOCATION, username=username, keys=keys, status="online", api_key=api_key, password=None)
            raise cherrypy.HTTPRedirect('/feed')  # This will take the user to their news feed
        else:
            raise cherrypy.HTTPRedirect('/login')  # This will take the user to their news feed

