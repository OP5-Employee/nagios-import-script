#!/usr/bin/env python

import pprint
import json

import requests
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
        block_name,
        block_num,
        template,
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


def web_post(host, auth, endpoint, data, ssl_check=True):
    target = '/'.join([
        host,
        'api',
        'config',
        endpoint,
        ])
    query_params = {'format': 'json'}
    content_headers = {'content-type': 'application/json'}
    json_payload = json.dumps(data)

    req = requests.post(
            target,
            auth=auth,
            verify=ssl_check,
            headers=content_headers,
            params=query_params,
            data=json_payload
            )

    if req.status_code != 200 \
            and req.status_code != 201 \
            and req.status_code != 409:
        print("{0}:{1}".format(req.status_code, req.reason)) 
        pprint.pprint(req.json())
        pprint.pprint(data)
    #else:
        #print("{0}:{1} {2}".format(req.status_code, req.reason, data))


def web_save(host, auth, save_check, ssl_check=True):
    save_target = '/'.join([
        host,
        'api',
        'config',
        'change'
        ])
    query_params = {'format': 'json'}
    content_headers = {'content-type': 'application/json'}

    req = requests.get(
        save_target,
        auth=auth,
        verify=ssl_check,
        params=query_params
        )

    if len(req.json()) >= save_check:
        print("Saving...")
        req = requests.post(
                save_target,
                auth=auth,
                verify=ssl_check,
                headers=content_headers,
                params=query_params,
                data=json.dumps('{}')
                )


def main(account, password, hostname, database, host, auth, ssl):
    if not ssl:
        print("Surpressing SSL warnings...")
        requests.packages.urllib3.disable_warnings()

    sql_where = "block_type = 'command' and template = false and override = false"

    db_conn = connection_open(account, password, hostname, database)
    returned_rows = fetch_content(db_conn, sql_where)
    connection_close(db_conn)

    for row in returned_rows:
        web_post(host, auth, 'command', row["content"], ssl)
        web_save(host, auth, 80, ssl)

    sql_where = "block_type = 'service' and template = true and override = false"

    db_conn = connection_open(account, password, hostname, database)
    returned_rows = fetch_content(db_conn, sql_where)
    connection_close(db_conn)

    for row in returned_rows:
        web_post(host, auth, 'service_template', row["content"], ssl)
        web_save(host, auth, 80, ssl)

    sql_where = "block_type = 'service' and template = true and override = true"

    db_conn = connection_open(account, password, hostname, database)
    returned_rows = fetch_content(db_conn, sql_where)
    connection_close(db_conn)

    for row in returned_rows:
        web_post(host, auth, 'service_template', row["content"], ssl)
        web_save(host, auth, 80, ssl)

    sql_where = "block_type = 'service' and template = false and override = false"

    db_conn = connection_open(account, password, hostname, database)
    returned_rows = fetch_content(db_conn, sql_where)
    connection_close(db_conn)

    for row in returned_rows:
        web_post(host, auth, 'service', row["content"], ssl)
        web_save(host, auth, 80, ssl)

    sql_where = "block_type = 'service' and template = false and override = true"

    db_conn = connection_open(account, password, hostname, database)
    returned_rows = fetch_content(db_conn, sql_where)
    connection_close(db_conn)

    for row in returned_rows:
        web_post(host, auth, 'service', row["content"], ssl)
        web_save(host, auth, 80, ssl)

    return 0


if __name__ == "__main__":
    account = 'dbaccount'
    password = 'dbpassword'
    #hostname = 'dbserver.example.com'
    hostname = 'localhost'
    database = 'consolidationdb'

    #host = 'https://172.16.1.4'
    host = 'https://monitor.example.com'
    auth = ('administrator', 'monitor')
    ssl = False

    main(account, password, hostname, database, host, auth, ssl)
