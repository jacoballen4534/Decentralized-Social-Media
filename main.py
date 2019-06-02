#!/usr/bin/python3
""" main.py
    
    COMPSYS302
    Author - Jacob Allen
    Last Edited: April 2019

    This program uses the CherryPy web server (from www.cherrypy.org).
"""
# Requires:  CherryPy 18.0.1  (www.cherrypy.org)
#            Python  (We use 3.5.x +)

import os
import os.path
import cherrypy
import cherrypy.lib.sessions
import logging
import MyApiEndpoints.landingPage
import MyApiEndpoints.feed
import MyApiEndpoints.login
import MyApiEndpoints.apis



# The address we listen for connections on
# LISTEN_IP = "0.0.0.0"
LISTEN_IP = "192.168.1.68"
LISTEN_PORT = 5001


def error_page_404(status, message, traceback, version):
    return "Sorry im not sure where you are trying to go. 404 ERROR!"


def runMainApp():
    #set up the config
    conf = {
        '/': {
            'tools.staticdir.root': os.path.abspath(os.getcwd()),
            'tools.encode.on': True,
            'tools.encode.encoding': 'utf-8',
            'tools.sessions.on': True,
            'tools.sessions.timeout': 60 * 3,  # timeout is in minutes, * 60 to get hours

            # The default session backend is in RAM. Other options are 'file',
            # 'postgres', 'memcached'. For example, uncomment:
            'tools.sessions.storage_class': cherrypy.lib.sessions.FileSession,
            'tools.sessions.storage_path': os.path.abspath(os.getcwd()) + '/temp/mysessions',
        },

        #configuration for the static assets directory
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': './static',
        },

        #once a favicon is set up, the following code could be used to select it for cherrypy
        '/favicon.ico': {
           'tools.staticfile.on': True,
           'tools.staticfile.filename': os.getcwd() + '/static/favicon.ico',
        },
    }

    cherrypy.site = {
        'base_path': os.path.abspath(os.getcwd())
    }

    # Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all of them)
    cherrypy.tree.mount(MyApiEndpoints.landingPage.LandingPage(), "/", conf)
    cherrypy.tree.mount(MyApiEndpoints.login.Login(), "/login", conf)
    cherrypy.tree.mount(MyApiEndpoints.feed.Feed(), "/feed", conf)
    cherrypy.tree.mount(MyApiEndpoints.apis.Api(), "/api", conf)
    logging.basicConfig(filename='Log.log', level=logging.DEBUG)

    # Tell cherrypy where to listen, and to turn autoreload on
    cherrypy.config.update({
        'server.socket_host': LISTEN_IP,
        'server.socket_port': LISTEN_PORT,
        'engine.autoreload.on': True,
        'error_page.404': error_page_404,
    })

    #cherrypy.tools.auth = cherrypy.Tool('before_handler', auth.check_auth, 99)

    print("========================================")
    print("             Jacob Allen")
    print("         Python Project - so far")
    print("========================================")

    # Start the web server
    cherrypy.engine.start()

    # And stop doing anything else. Let the web server take over.
    cherrypy.engine.block()


#Run the function to start everything
if __name__ == '__main__':
    runMainApp()
