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
        """The landing page for my sight. If the user is already logged in, take them to their home page,
        otherwise, take them to the login page."""

        username = cherrypy.session.get('username')
        api_key = cherrypy.session.get('api_key')
        private_key = cherrypy.session.get('private_key')  #TODO: Maybe just store full key object for ease of use.
        #TODO: Note that they dont need an encryption key, as they can manualy enter priv key. Will not be able to access private data tho
        if username is not None and private_key is not None and api_key is not None:
            raise cherrypy.HTTPRedirect('/feed')  # This will take the user to their news feed
        else:
            raise cherrypy.HTTPRedirect('/login')  # This will take the user to their news feed

