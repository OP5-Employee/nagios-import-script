#!/usr/bin/env python

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


def fetch_content(db, where_clause):
    sql = """
    SELECT
        filename,
        block_type,
        override,
        content
    FROM
        content
    WHERE
        {0}
    """

    formatted_sql = sql.format(where_clause)

    print(formatted_sql)

    cursor = cursor_open(db)
    cursor.execute(formatted_sql)
    rows = cursor_fetch_all(cursor)
    cursor_close(cursor)

    return rows


def main(account, password, hostname, database):
    sql_where = "block_type = 'timeperiod' and override = false and template = false"

    db_conn = connection_open(account, password, hostname, database)
    returned_rows = fetch_content(db_conn, sql_where)
    connection_close(db_conn)

    for row in returned_rows:
        pprint.pprint(row)

    return 0


if __name__ == "__main__":
    account = 'consolidator'
    password = 'dbpass'
    #hostname = 'jackalope.home.dangertoaster.com'
    hostname = '172.27.77.111'
    database = 'consolidationdb'

    main(account, password, hostname, database)
