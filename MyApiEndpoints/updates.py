import cherrypy
import json
import ApisAndHelpers.loginServerApis as loginServerApis
import db.getData as getData
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
            return ""

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["POST"])
    # @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def update_new_broadcasts(self):
        """This endpoint gets called by each client, from their browser. It will send any new messages in html string"""
        try:
            data = cherrypy.request.json
            last_message_id = int(data.get("last_message"))

            message_template = env.get_template('/html/newMessage.html')

            username = cherrypy.session.get('username')
            api_key = cherrypy.session.get('api_key')

            # If they shouldnt be here. Kick them back to login.
            if username is None or api_key is None:
                raise cherrypy.HTTPRedirect('/')
            print("Request: " + str(data.get("request")) + " from: " + str(username))

            new_messages = getData.get_public_broadcast(last_broadcast_id=last_message_id, limit=-1)

            temp = json.dumps(message_template.module.display_broadcast(broadcasts=new_messages))
            return temp
        except Exception as e:
            print(e)
            return ""

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["POST"])
    # @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def search_broadcasts(self):
        """Users can call this function via the search box. It will return any messages that have the search term
        as part of the sender name."""
        try:
            data = cherrypy.request.json
            message_from = data.get("message_from")
            if len(message_from) <= 0:  # Should be able to call with nothing, but check anyway
                return ""

            message_template = env.get_template('/html/newMessage.html')

            username = cherrypy.session.get('username')
            api_key = cherrypy.session.get('api_key')

            # If they shouldnt be here. Kick them back to login.
            if username is None or api_key is None:
                raise cherrypy.HTTPRedirect('/')
            print("Request: " + str(data.get("request")) + " from: " + str(username))

            new_messages = getData.search_database(message_from=message_from)

            temp = json.dumps(message_template.module.display_broadcast(broadcasts=new_messages))
            return temp
        except Exception as e:
            print(e)

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["POST"])
    # @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def send_broadcast(self):
        """Clients call this endpoint via the send broadcast box. It will take a message and send it to all other
        servers"""
        import MyApiEndpoints.apis as my_apis
        import pickle
        try:
            data = cherrypy.request.json
            message = data.get("message")
            if len(message) <= 0:  # Should be able to call with nothing, but check anyway
                return

            username = cherrypy.session.get('username')
            api_key = cherrypy.session.get('api_key')
            pickled_keys = cherrypy.session.get("pickled_keys")

            # Set the user status to offline before signing out
            keys = pickle.loads(pickled_keys)
            print("Request: " + str(data.get("request")) + " from: " + str(username))
            users = loginServerApis.list_users(username=username, api_key=api_key, password=None)
            my_apis.send_broadcast(username=username, message=message, send_to_dict=users, keys=keys, api_key=api_key,
                                   password=None)
        except Exception as e:
            print(e)

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["POST"])
    @cherrypy.tools.json_in()
    def call_ping_check(self):
        """Clients call this endpoint every 5 minutes to initiate a ping check on all other servers"""
        import MyApiEndpoints.apis as my_apis
        try:
            data = cherrypy.request.json

            username = cherrypy.session.get('username')
            api_key = cherrypy.session.get('api_key')

            print("Request: " + str(data.get("request")) + " from: " + str(username))
            users = loginServerApis.list_users(username=username, api_key=api_key, password=None)
            my_apis.call_ping_check(send_to_dict=users)
        except Exception as e:
            print(e)
