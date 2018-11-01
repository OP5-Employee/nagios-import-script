# nagios-import-script
Script to import Nagios configs

This is really dirty. It started out great, but then I kind of piled on hacks as needed because I needed this to work right now. Don't judge me, please.

It's single threaded and mostly network IO bound. Loading the files into Postgres isn't bad; it's waiting on all the network calls. This is designed to work on three separate machines, one machine, or some combination there of, although it doesn't support a separate read Db instance now that I think about it.

Anyway...

# Notes about consolidator.py

## Dependencies

### Python

StdLib:
- os
- logging
- argparse
- re
- json

3rd party:
- psycopg2
- psycopg2-extras

### General

- PostgreSQL 9.6+ (JSONB)
- Python 2.6+

## Setup

### PostgreSQL Setup

References:
- https://wiki.postgresql.org/wiki/YUM\_Installation
- https://www.postgresql.org/docs/current/static/app-createdb.html
- https://www.postgresql.org/docs/current/static/app-createuser.html
- https://www.postgresql.org/docs/current/static/auth-pg-hba-conf.html

1. Install postgres.
1. Initialize db.
1. Start postgres.
	1. Optionally, enable postgres to start on boot.
1. Become the postgres user to create the database and user. `sudo -u postgres -i`
1. Create account with the `createuser` script.

```
createuser -P <accountname>
```

1. Create db with the `createdb` script and set the owner to the newly created account.

```
createdb -O <accountname> <dbname>
```

1. Exit `postgres` user session.
1. Edit `pg_hba.conf` to enable access to the postgres service.
	1. Optionally, edit the `postgres.conf` file to allow network access.
1. Restart the postgres service to get the changes to take affect.
1. Edit the database sections in the config file.
1. Test the new postgres account with `psql`.

```
psql -h localhost -U <accountname> -d <accountdb>
```

1. If login was successful, run the `createdb.py` script with the config file passed as an argument to setup the import database.

### Edit the config file

1. Edit the config to set the database details.

### Setup the database

1. Run `./createdb.py consolidator.conf` to create the database.

## Running Db Based Import

1. Run `consolidator.py` pointing to the config file, OP5 Monitor install, and OP5 Monitor account credentials.
```
./consolidator.py consolidator.conf https://172.16.1.4 administrator monitor /path/to/config/nagios > captured-output.txt
```

There is quite a bit of output becasue I didn't have time to really troubleshoot logger in the class.

## Project file description

- `README.md`: Readme and other random notes.
- `consolidator.conf`: Ini style config file which can be used to the ConfigParser module.
- `createdb.py`: Script to setup the PostgreSQL database.
- `consolidator.py`: PostgreSQL backed nagios importer.
- `interactive_setup.py`: Script to setup an interactive shell for testing. ex: `bpython -i interactive_setup.py`
- `file_cleaner.py`: Script to test block parsing.
- `db_query.py`: Script to setup an interactive shell for db testing or a standalone script to test db queries.

## Logic

1. Parse files.
1. Add code blocks to database.
1. Build config files by querying database for specific types.

```
Block dictionary structure:
"{
    "filename": "/path/to/file",
    "block_num": 0,
    "block_type": "<host|service|etc.>",
    "template": "<True|False",
    "object_name": "<name>",
    "content": {
        "use": "default_http_check",
        "<key>": "<value>",
        ...
    }
}

List structure:
[
    {"<filename>":{...}},
    {"<filename>":{...}},
    ...
]

Nagios File Structure:
define service {
        check_command           check_http!--ssl -H 74.121.193.2 -ffollow
        use                     default_https_check
        host_name               travelport-us.cloudapp.net
}

define contact {

}

define contactgroup {

}

...
```

## Database Structure

### Metadata Table

```
CREATE TABLE IF NOT EXISTS metadata (
    entry_type TEXT,
    data TEXT,
    PRIMARY KEY(entry_type, data)
)
```

### Content Table

```
CREATE TABLE IF NOT EXISTS content (
    filehash TEXT NOT NULL,
    filename TEXT NOT NULL,
    block_num INTEGER CHECK (block_num >= 0),
    block_type TEXT,
    override BOOLEAN NOT NULL,
    template BOOLEAN NOT NULL,
    content BSON NOT NULL,
    PRIMARY KEY(filehash, block_num, block_type)
)
CREATE INDEX ON filename
```

## Files

* Skip everything that starts with "#!/"

### Config Files
* .cfg
* *.cfg
* *.cfg.override
* override.ov
* *.host-group
* *.tv

### Unknown (Ignoring for now)
* *.cfge
* *.overridee
* *.cfg~e
* *~~
* *~

### Ignore Files
* *.bak
* *.back
* *.backup
* *.txt
* *.OFF
* .gitignore
* *.bk
* *.skel
* *.old
* *.sh
* *.pl
* *.py
* *.rpmnew
* *.disabled
* *.off
* passwd
* *.sample

### Ignore Dirs
* .git

## Psycopg2 Notes

Return cursor objects as python dictionaries.
```
cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

# conn.cursor will return a cursor object, you can use this query to perform queries

# note that in this example we pass a cursor_factory argument that will
# dictionary cursor so COLUMNS will be returned as a dictionary so we
# can access columns by their name instead of index.
```

## Bugs

The Nagios parsing logic still needs to be beat on. There are probably going to be bugs.

The script doesn't delete anything in the database, but it will update the database entries if there is a collision.

The script isn't very smart. It doesn't do dependency mapping, so things will fail due to being out of order. :( Luckily, running the script multiple times will fix this. 
