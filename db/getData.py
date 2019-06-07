import sqlite3
from datetime import datetime


def get_public_broadcast(last_broadcast_id, limit):
    """This returns the last (upto limit) broadcasts. If this is the initial page load, user limit of 20, otherwise -1
    for all"""

    conn = None
    broadcasts = []
    try:
        conn = sqlite3.connect("./db/database.db")
        c = conn.cursor()
        c.execute("""SELECT id, message, sender, timestamp FROM broadcasts WHERE id > ? ORDER BY id DESC LIMIT ?""",
                  (last_broadcast_id, limit))
        rows = c.fetchall()
        print("Retrieving new messages from db")

        for row in rows:
            broadcasts.append({
                'id': row[0],
                'message': row[1],
                'sender': row[2],
                'timestamp': datetime.fromtimestamp(row[3]).strftime('%Y-%m-%d %H:%M:%S'),
            })

    except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
        print(e)
    finally:
        if conn is not None:
            conn.close()
        return broadcasts


def search_database(message_from):
    """This returns all the broadcasts sent from "message_from"""
    conn = None
    broadcasts = []
    try:
        conn = sqlite3.connect("./db/database.db")
        c = conn.cursor()
        c.execute("""SELECT id, message, sender, timestamp FROM broadcasts WHERE instr(sender, ?) > 0 ORDER BY id DESC""", (message_from, ))
        rows = c.fetchall()
        print("Retrieving new messages from db")

        for row in rows:
            broadcasts.append({
                'id'       : row[0],
                'message'  : row[1],
                'sender'   : row[2],
                'timestamp': datetime.fromtimestamp(row[3]).strftime('%Y-%m-%d %H:%M:%S'),
            })

    except (Exception, sqlite3.OperationalError, sqlite3.IntegrityError) as e:
        print(e)
    finally:
        if conn is not None:
            conn.close()
        return broadcasts
