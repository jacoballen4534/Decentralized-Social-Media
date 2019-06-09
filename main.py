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
import MyApiEndpoints.updates
import MyApiEndpoints.privateMessages
import sqlite3
import db.addData as addData


# The address we listen for connections on
# LISTEN_IP = "0.0.0.0"
LISTEN_IP = "192.168.1.68"
LISTEN_PORT = 5001
LOCATION = "2"


# initialize database
def init_db():
    """If the database doesnt allready exsist, create it, then ensure the desired tables are there, Only create them
    if they arnt allready there."""
    conn = None
    try:
        conn = sqlite3.connect("./db/database.db")
        conn.execute("PRAGMA foreign_key = 1")
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS `broadcasts` (
                    `id`            INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
                    `message`       TEXT NOT NULL,
                    `sender`        TEXT NOT NULL,
                    `timestamp`     INTEGER NOT NULL,
                    `sender_pubkey` TEXT NOT NULL,
                    `signature`     TEXT NOT NULL UNIQUE 
                );""")
        c.execute("""CREATE TABLE IF NOT EXISTS `private_messages` (
                    `id`            INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
                    `message`        TEXT NOT NULL,
                    `sender`         TEXT NOT NULL,                    
                    `receiver`       TEXT NOT NULL,
                    `timestamp`      INTEGER NOT NULL,                    
                    `sender_pubkey`  TEXT NOT NULL,
                    `receiver_pubkey`TEXT NOT NULL,
                    `signature`      TEXT NOT NULL
                );""")
        c.execute("""CREATE TABLE IF NOT EXISTS `all_seen_users` (
                            `username`              VARCHAR(100) PRIMARY KEY UNIQUE NOT NULL,
                            `incoming_pubkey`       TEXT NOT NULL,
                            `connection_updated_at` INTEGER NOT NULL,                    
                            `connection_address`    VARCHAR(50) NOT NULL,
                            `connection_location`   INTEGER NOT NULL
                        );""")
        c.execute("""CREATE TABLE IF NOT EXISTS `favourite_broadcast` (
                            `username`      VARCHAR(100) NOT NULL,
                            `pubkey`        TEXT NOT NULL,
                            `timestamp`     INTEGER NOT NULL,
                            `favourite_signature` TEXT NOT NULL, 
                            FOREIGN KEY (favourite_signature) REFERENCES broadcasts(signature)
                            ON UPDATE set null
                            ON DELETE CASCADE 
                        );""")
        # To limit people favouring a tweet once
        c.execute("""CREATE UNIQUE INDEX username_favourite ON favourite_broadcast (username, favourite_signature)""")
    except Exception as e:
        print(e)
    finally:
        if conn is not None:
            conn.close()


def error_page_404(status, message, traceback, version):
    return "Sorry im not sure where you are trying to go. 404 ERROR!"


def runMainApp():
    # Setup the database
    init_db()
    # set up the config
    conf = {
        '/'           : {
            'tools.staticdir.root'        : os.path.abspath(os.getcwd()),
            'tools.encode.on'             : True,
            'tools.encode.encoding'       : 'utf-8',
            'tools.sessions.on'           : True,
            'tools.sessions.timeout'      : 60 * 3,  # timeout is in minutes, * 60 to get hours

            # Comment this out for ram based (can store objects). Uncomment for file based
            'tools.sessions.storage_class': cherrypy.lib.sessions.FileSession,
            'tools.sessions.storage_path' : os.path.abspath(os.getcwd()) + '/temp/mysessions',
        },

        # configuration for the static assets directory
        '/static'     : {
            'tools.staticdir.on' : True,
            'tools.staticdir.dir': './static',
        },

        # once a favicon is set up, the following code could be used to select it for cherrypy
        '/favicon.ico': {
            'tools.staticfile.on'      : True,
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
    cherrypy.tree.mount(MyApiEndpoints.privateMessages.PrivateMessages(), "/privateMessages", conf)
    cherrypy.tree.mount(MyApiEndpoints.apis.Api(), "/api", conf)
    cherrypy.tree.mount(MyApiEndpoints.updates.Updates(), "/updates", conf)

    # Tell cherrypy where to listen, and to turn autoreload on
    cherrypy.config.update({
        'server.socket_host'  : LISTEN_IP,
        'server.socket_port'  : LISTEN_PORT,
        'engine.autoreload.on': True,
        'error_page.404'      : error_page_404,
    })

    # cherrypy.tools.auth = cherrypy.Tool('before_handler', auth.check_auth, 99)

    print("========================================")
    print("             Jacob Allen")
    print("         Python Project - so far")
    print("========================================")

    # Start the web server
    cherrypy.engine.start()

    # And stop doing anything else. Let the web server take over.
    cherrypy.engine.block()


# Run the function to start everything
if __name__ == '__main__':
    runMainApp()
