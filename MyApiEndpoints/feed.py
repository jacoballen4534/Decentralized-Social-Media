import pprint
import urllib.request
import cherrypy
import ApisAndHelpers.loginServerApis as loginApi
import json
import pickle
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader('static'), autoescape=True)


class Feed:
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        error_template = env.get_template('/html/404Error.html')
        cherrypy.response.status = 404
        return error_template.render()

    @cherrypy.expose
    def index(self, *args, **kwargs):
        import db.getData as getData
        """This is the users home page. This is where new public messages are posted."""
        feed_template = env.get_template('/html/feed.html')

        username = cherrypy.session.get('username')
        api_key = cherrypy.session.get('api_key')
        pickled_keys = cherrypy.session.get("pickled_keys")

        # If they shouldnt be here. Kick them back to login.
        if username is None or api_key is None or pickled_keys is None:
            raise cherrypy.HTTPRedirect('/')

        online_users = loginApi.list_users(username=username, api_key=api_key)
        # Get the last (upto) 20 messages to display on the home page.
        broadcasts = getData.get_public_broadcast(last_broadcast_id=0, limit=20)
        return feed_template.render(username=username, users=online_users, broadcasts=broadcasts)
