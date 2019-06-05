import pprint
import urllib.request
import cherrypy
import json
import time
import ApisAndHelpers.loginServerApis as loginServerApis
import ApisAndHelpers.requests as request_helper
import ApisAndHelpers.crypto as crypto
import sqlite3


def add_public_broadcast(sender, sender_pubkey, timestamp, message):
    conn = None
    try:
        conn = sqlite3.connect("./database.db")
        c = conn.cursor()
        c.execute("""INSERT INTO broadcasts ()""")
        print("Connects")

    except (sqlite3.OperationalError, sqlite3.IntegrityError):
        pass
    finally:
        if conn is not None:
            conn.close()
