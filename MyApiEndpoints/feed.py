import pprint
import urllib.request
import cherrypy
import ApisAndHelpers.loginServerApis as loginApi
import json
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
        """This is the users home page. This is where new public messages are posted."""
        feed_template = env.get_template('/html/feed.html')

        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')
        api_key = cherrypy.session.get('api_key')
        private_key = cherrypy.session.get('private_key')
        if username is not None and password is not None and api_key is not None:
            online_users = loginApi.list_users(username, password)
            return feed_template.render(username=username, users=online_users)
        else:
            raise cherrypy.HTTPRedirect('/')
