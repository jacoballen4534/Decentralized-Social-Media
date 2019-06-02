import pprint
import urllib.request
import cherrypy
import exampleApiAccess.apiHelpers as acc
import json
import MyApiEndpoints.login
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
        """The landing page for my sight. If the user is allready loged in, take them to their home page,
        otherwise, take them to the login page."""
        # Todo: Add private key
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')
        api_key = cherrypy.session.get('api_key')
        if username is not None and password is not None and api_key is not None:
            raise cherrypy.HTTPRedirect('/feed')  # This will take the user to their news feed
        else:
            raise cherrypy.HTTPRedirect('/login')  # This will take the user to their news feed

