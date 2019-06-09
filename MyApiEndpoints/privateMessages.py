import pprint
import urllib.request
import cherrypy
import ApisAndHelpers.loginServerApis as loginApi
import json
import pickle
import markupsafe
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader('static'), autoescape=True)


class PrivateMessages:
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        error_template = env.get_template('/html/404Error.html')
        cherrypy.response.status = 404
        return error_template.render()

    @cherrypy.expose
    def index(self, *args, **kwargs):
        """This is where the user can see their private messages."""
        import db.getData as getData
        private_template = env.get_template('/html/privateMessages.html')

        username = cherrypy.session.get('username')
        api_key = cherrypy.session.get('api_key')
        pickled_keys = cherrypy.session.get("pickled_keys")

        # If they shouldnt be here. Kick them back to login.
        if username is None or api_key is None or pickled_keys is None:
            raise cherrypy.HTTPRedirect('/')

        # Get a list of all users to message
        user_list = getData.get_all_seen_users()
        return private_template.render(username=username, user_list=user_list, page_title="Private Messages")
