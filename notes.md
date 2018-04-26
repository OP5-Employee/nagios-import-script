# Notes about consolidator.py

## Dependencies

StdLib:
- os
- logging
- argparse
- re
- json

3rd party:
- psycopg2
- psycopg2-extras

## Building Monolithic Config Files

1. Parse files.
1. Add code blocks to database.
    1. Query database for duplicate define blocks.
    1. Merge define blocks based on file precedence.
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
