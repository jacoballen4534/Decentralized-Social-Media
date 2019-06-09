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
    """This returns all the broadcasts sent from people with username containing 'message_from' """
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


def get_public_broadcasts_since(since):
    """This returns all broadcasts after 'since'"""

    conn = None
    broadcasts = []
    try:
        conn = sqlite3.connect("./db/database.db")
        c = conn.cursor()
        c.execute("""SELECT message, sender, timestamp, sender_pubkey, signature FROM broadcasts WHERE timestamp > ?""",
                  (since,))
        rows = c.fetchall()
        print("Retrieving new messages from db")

        for row in rows:
            broadcasts.append({
                'message': row[0],
                'sender': row[1],
                'timestamp': row[2],
                'sender_pubkey': row[3],
                'message_signature': row[4]
            })

    except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
        print(e)
    finally:
        if conn is not None:
            conn.close()
        return broadcasts


def get_all_seen_users():
    """Returns a list of all users that have been seen (reported)'"""

    conn = None
    user_list = []
    try:
        conn = sqlite3.connect("./db/database.db")
        c = conn.cursor()
        c.execute("""SELECT username, incoming_pubkey, connection_updated_at, connection_address, connection_location FROM all_seen_users""")
        rows = c.fetchall()
        print("Retrieving new messages from db")

        for row in rows:
            user_list.append({
                'username': row[0],
                'incoming_pubkey': row[1],
                'connection_updated_at': row[2],
                'connection_address': row[3],
                'connection_location': row[4]
            })

    except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
        print(e)
    finally:
        if conn is not None:
            conn.close()
        return user_list


def retreive_private_messages(sender, receiver):
    """Returns a list of all private messages from another user'"""

    conn = None
    user_list = []
    try:
        conn = sqlite3.connect("./db/database.db")
        c = conn.cursor()
        c.execute(
            """SELECT id, message, sender, receiver, timestamp, sender_pubkey, receiver_pubkey, signature FROM 
            private_messages WHERE sender = ? AND receiver = ?""", (sender, receiver,))
        rows = c.fetchall()
        print("Retrieving new messages from db")

        for row in rows:
            user_list.append({
                'id': row[0],
                'message': row[1],
                'sender': row[2],
                'receiver': row[3],
                'timestamp': row[4],
                'sender_pubkey': row[5],
                'receiver_pubkey': row[6],
                'signature': row[7],
            })

    except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
        print(e)
    finally:
        if conn is not None:
            conn.close()
        return user_list
