#!/usr/bin/env python
# Stdlib
import argparse
import ConfigParser

# 3rd-party
import psycopg2


def main(account, password, database, host=None):
    dbconnect = None
    tables = (
        """
        CREATE TABLE IF NOT EXISTS metadata (
            entry_type TEXT,
            data TEXT,
            PRIMARY KEY(entry_type, data)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS content (
            filehash TEXT NOT NULL,
            filename TEXT NOT NULL,
            block_num INTEGER NOT NULL CHECK (block_num >= 0),
            block_type TEXT NOT NULL,
            block_name TEXT DEFAULT NULL,
            override BOOLEAN NOT NULL,
            template BOOLEAN NOT NULL,
            content JSONB NOT NULL,
            PRIMARY KEY(filehash, block_num, block_type)
        );
        """,
    )

    indexes = (
        """
        CREATE INDEX IF NOT EXISTS content_filename_idx ON content (filename);
        """,
        """
        CREATE INDEX IF NOT EXISTS content_blocktype_idx ON content (block_type);
        """,
        """
        CREATE INDEX IF NOT EXISTS content_blocktype_template_idx ON content(block_type, template);
        """,
        """
        CREATE INDEX IF NOT EXISTS content_blocktype_override_idx ON content(block_type, override);
        """,
        """
        CREATE INDEX IF NOT EXISTS content_content_gidx ON content USING GIN (content);
        """,

    )
    try:
        dbconnect = psycopg2.connect(
            user=account,
            password=password,
            host=host,
            dbname=database
        )

        print("Checking database connection...")
        cursor = dbconnect.cursor()
        cursor.execute('SELECT version()')
        db_version = cursor.fetchone()
        print("\nPassed!\nPostgreSQL database version:")
        for entry in db_version[0].split(','):
            print("\t{0}".format(entry))
        print("\nCreating tables...")

        for table in tables:
            cursor.execute(table)

        for index in indexes:
            cursor.execute(index)

        cursor.close()
        dbconnect.commit()

    except (Exception, psycopg2.DatabaseError) as error:
        print(error)

    finally:
        if dbconnect is not None:
            dbconnect.close()
        print("Done.")

    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Initializes PostgreSQL database."
    )
    parser.add_argument(
        "config",
        help="Configuration file with database settings."
    )
    args = parser.parse_args()

    config = ConfigParser.ConfigParser()
    config.read(args.config)

    account = config.get("database", "account")
    password = config.get("database", "password")
    database = config.get("database", "database")
    host = config.get("database", "host")

    main(account, password, database, host)
