import pprint

import psycopg2
from psycopg2.extras import RealDictCursor


def connection_open(account, password, hostname, database):
    connection = None

    try:
        connection = psycopg2.connect(
            user=account,
            password=password,
            host=hostname,
            dbname=database,
            cursor_factory=RealDictCursor
        )
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        return connection


def connection_commit(connection):
    connection.commit()


def connection_close(connection):
    if connection is not None:
        connection.close()


def cursor_open(connection):
    return connection.cursor()


def cursor_close(cursor):
    cursor.close()


def cursor_fetch_all(cursor):
    return cursor.fetchall()


def cursor_row_count(cursor):
    return cursor.rowcount


account = 'consolidator'
password = 'dbpass'
hostname = 'postgresql.server.domain.tld'
database = 'consolidationdb'
