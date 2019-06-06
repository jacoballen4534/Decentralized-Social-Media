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
import sqlite3
import threading
import db.messageStreamer
import db.addData as addData


# The address we listen for connections on
LISTEN_IP = "0.0.0.0"
# LISTEN_IP = "192.168.1.68"
LISTEN_PORT = 5001


# initialize database
def init_db():
    """If the database doesnt allready exsist, create it, then ensure the desired tables are there, Only create them
    if they arnt allready there."""
    conn = None
    try:
        conn = sqlite3.connect("./db/database.db")
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS `broadcasts` (
                    `id`            INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
                    `message`       TEXT NOT NULL,
                    `sender`        TEXT NOT NULL,
                    `timestamp`     INTEGER NOT NULL,
                    `sender_pubkey` TEXT NOT NULL,
                    `signature`     TEXT NOT NULL
                );""")
        c.execute("""CREATE TABLE IF NOT EXISTS `messages` (
                    `id`            INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
                    `message`        TEXT NOT NULL,
                    `sender`         TEXT NOT NULL,                    
                    `receiver`       TEXT NOT NULL,
                    `timestamp`      INTEGER NOT NULL,                    
                    `sender_pubkey`  TEXT NOT NULL,
                    `receiver_pubkey`TEXT NOT NULL,
                    `signature`      TEXT NOT NULL
                );""")
    except Exception as e:
        print(e)
    finally:
        if conn is not None:
            conn.close()


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
            'tools.sessions.timeout': 60 * 10,  # timeout is in minutes, * 60 to get hours

            # Comment this out for ram based (can store objects). Uncomment for file based
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

    cherrypy.config.update({
        'server.socket_host': LISTEN_IP,
        'server.socket_port': LISTEN_PORT,
        'server.thread_pool': 25,
        'server.socket_queue_size': 10,
        'engine.autoreload.on': True,
        'error_page.404': error_page_404,
    })
    #cherrypy.tools.auth = cherrypy.Tool('before_handler', auth.check_auth, 99) TODO: Look at

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
    # Setup the database on startup
    cherrypy.engine.subscribe("start", init_db)
    cherrypy.engine.subscribe("store_new_broadcast", db.addData.add_public_broadcast)

    runMainApp()




#Set up different log files
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')


def setup_logger(name, log_file, level=logging.INFO):
    """This sets up various log files, for different severity"""
    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    return logger


info_logger = setup_logger('info_logger', 'InfoLog.log', logging.INFO)
private_data_logger = setup_logger('private_data_logger', 'private_data_logger.log', logging.INFO)
debug_logger = setup_logger('debug_logger', 'DebugLog.log', logging.DEBUG)

