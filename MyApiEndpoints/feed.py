import pprint
import urllib.request
import cherrypy
import exampleApiAccess.apiHelpers as acc
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
        home_template = env.get_template('/html/feed.html')

        if 'username' in cherrypy.session and 'password' in cherrypy.session and 'second_password' in cherrypy.session:
            username = cherrypy.session['username']
            return home_template.render(username=username)
        else:
            raise cherrypy.HTTPRedirect('/')
