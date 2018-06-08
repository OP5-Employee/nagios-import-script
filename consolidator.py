#!/usr/bin/env python

import os
import logging
import argparse
import ConfigParser
import ast
import re
import json
import hashlib
from pprint import pprint
from time import sleep

import requests
import psycopg2
from psycopg2.extras import RealDictCursor


class OP5MonitorHTTP:
    params = {'format': 'json'}
    header = {'content-type': 'application/json'}
    ssl_check = True
    nop = False
    pop = False
    save_check = 0

    def __init__(self, server_url, account, password, save_interval):
        #self.__class__.logger = logging.getLogger(self.class.__class__.__name__)
        self.url = "/".join(
            [
                server_url,
                "api",
                "config"
            ]
        )
        self.auth_pair = (account, password)
        self.save_interval = save_interval

    def disable_ssl(self):
        print("Supressing SSL warnings...")
        self.ssl_check = False
        requests.packages.urllib3.disable_warnings()

    def set_no_op(self):
        self.nop = True

        if self.pop:
            self.pop = False

    def set_part_op(self):
        self.pop = True

        if self.nop:
            self.nop = False

    def print_error(self, status_code, http_text, content):
        error_text = ast.literal_eval(http_text)
        print("Status code: {0}\tError: {1}".format(
            status_code,
            error_text["full_error"]
        ))
        pprint(content)

    def build_target(self, endpoint, endpoint_obj=''):
        return "/".join([self.url, endpoint, endpoint_obj])

    def check_save_interval(self):
        if self.save_check < self.save_interval:
            self.save_check += 1
        elif self.save_check > 0:
            self.save()

    def check_status_code(self, http_obj, datapayload={}):
        if http_obj.status_code != 200 \
           and http_obj.status_code != 201:
            self.print_error(http_obj.status_code,
                             http_obj.text, datapayload)

    def save(self):
        self.save_check = 0

        server_target = self.build_target("change")

        http_save = requests.get(
            server_target,
            verify=self.ssl_check,
            auth=self.auth_pair,
            params=self.params
        )

        if json.loads(http_save.text) == []:
            print("Save queue empty. Nothing to do.")
        else:
            http_save = requests.post(
                server_target,
                verify=self.ssl_check,
                auth=self.auth_pair,
                params=self.params,
                headers=self.header,
                data=json.dumps({})
            )

            sleep(3)


        if http_save.status_code != 200 \
           and http_save.status_code != 201:
            self.print_error(http_save.status_code,
                             http_save.text,
                             "Save function, no data.")

        return http_save.status_code

    def patch(self, endpoint, endpoint_obj, datalist):
        if self.nop:
            print("No op specified. Not patching.")
            return 0

        print("Patching object...")
        for datapayload in datalist:
            server_target = self.build_target(endpoint, endpoint_obj)
            http_patch = requests.patch(
                server_target,
                verify=self.ssl_check,
                auth=self.auth_pair,
                params=self.params,
                headers=self.header,
                data=json.dumps(datapayload["content"])
            )

            self.check_status_code(http_patch, datapayload)
            self.check_save_interval()

        self.check_save_interval()

        return http_patch.status_code

    def put(self, endpoint, endpoint_obj, datalist):
        if self.nop:
            print("No op specified. Not overwriting.")
            return 0

        print ("Putting object and overwriting...")
        server_target = self.build_target(endpoint, endpoint_obj)

        for datapayload in datalist:
            http_put = requests.put(
                server_target,
                verify=self.ssl_check,
                auth=self.auth_pair,
                params=self.params,
                headers=self.header,
                data=json.dumps(datapayload["content"])
            )

            self.check_status_code(http_put, datapayload)
            self.check_save_interval()

        return http_put.status_code

    def post(self, endpoint, datalist, update_on_duplicate=False):
        if self.nop:
            print("No op specified. Not posting.")
            return 0

        print("Posting object...")
        server_target = self.build_target(endpoint)

        for datapayload in datalist:
            http_post = requests.post(
                server_target,
                verify=self.ssl_check,
                auth=self.auth_pair,
                params=self.params,
                headers=self.header,
                data=json.dumps(datapayload["content"])
            )

            if http_post.status_code == 409 \
               and update_on_duplicate == True:
                self.put(endpoint, datapayload["block_name"], [datapayload])
            elif http_post.status_code == 409:
                print("409 code")
            else:
                self.check_status_code(http_post, datapayload)

            self.check_save_interval()

        self.save()

        return http_post.status_code

    def get(self, endpoint):
        if self.nop:
            print("No op specified. Not getting endpoint.")
            return 0

        print("Getting object...")
        server_target = self.build_target(endpoint)
        http_get = requests.get(
            server_target,
            verify=self.ssl_check,
            auth=self.auth_pair,
            params=self.params,
            headers=self.header,
        )

        self.check_status_code(http_get)

        return (http_get.status_code, json.loads(http_get.text))


class ConfigFileObj:
    logger = logging.getLogger(__name__)
    common = {
        "script": None,
        "comment": None,
        "blankline": None,
        "block_start": None,
        "block_end": None
    }
    block = dict()
    field = dict()
    replacements = dict()
    override_file = None

    def __init__(self, config):
        self.override_file = re.compile(
            ast.literal_eval(
                config.get("include", "override_file")
            )
        )
        self.common["script"] = re.compile(
            ast.literal_eval(
                config.get("cfgfile_common", "script")
            )
        )
        self.common["comment"] = re.compile(
            ast.literal_eval(
                config.get("cfgfile_common", "comment")
            )
        )
        self.common["blankline"] = re.compile(
            ast.literal_eval(
                config.get("cfgfile_common", "blankline")
            )
        )
        self.common["block_start"] = re.compile(
            ast.literal_eval(
                config.get("cfgfile_common", "block_start")
            )
        )
        self.common["block_end"] = re.compile(
            ast.literal_eval(
                config.get("cfgfile_common", "block_end")
            )
        )

        for cfgpair in config.items("cfgfile_block_type"):
            self.block[cfgpair[0]] = re.compile(
                ast.literal_eval(
                    cfgpair[1]
                )
            )

        for cfgpair in config.items("block_field"):
            self.field[cfgpair[0]] = re.compile(
                ast.literal_eval(
                    cfgpair[1]
                )
            )

        search_type = "common"
        self.replacements[search_type] = dict()
        for cfgpair in config.items("cfgfile_replacements_common"):
            self.replacements[search_type][cfgpair[0]] = re.compile(
                ast.literal_eval(cfgpair[1])
            )

        search_type = "timeperiod"
        self.replacements[search_type] = dict()
        for cfgpair in config.items("cfgfile_replacements_timeperiod"):
            self.replacements[search_type][cfgpair[0]] = re.compile(
                ast.literal_eval(cfgpair[1])
            )

        search_type = "host"
        self.replacements[search_type] = dict()
        for cfgpair in config.items("cfgfile_replacements_host_template"):
            self.replacements[search_type][cfgpair[0]] = re.compile(
                ast.literal_eval(cfgpair[1])
            )

        search_type = "service"
        self.replacements[search_type] = dict()
        for cfgpair in config.items("cfgfile_replacements_service"):
            self.replacements[search_type][cfgpair[0]] = re.compile(
                ast.literal_eval(cfgpair[1])
            )

    def print_common(self, verbose=True):
        logger = logging.getLogger(__name__)
        if verbose:
            print("Common Regex:")
        for pair in self.common.items():
            key, val = pair
            if verbose:
                print("{0}\t{1}".format(key, val.pattern))
            logger.info("Common Regex Pattern: {0}\t{1}".format(
                key, val.pattern
            ))

    def print_block(self, verbose=True):
        logger = logging.getLogger(__name__)
        if verbose:
            print("Config Block Regex:")
        for pair in self.block.items():
            key, val = pair
            if verbose:
                print("{0}\t{1}".format(key, val.pattern))
            logger.info("Config Block Regex Pattern: {0}\t{1}".format(
                key, val.pattern
            ))

    def print_fields(self, verbose=True):
        logger = logging.getLogger(__name__)
        if verbose:
            print("Config Field Regex:")
        for pair in self.field.items():
            key, val = pair
            if verbose:
                print("{0}\t{1}".format(key, val.pattern))
            logger.info("Config Field Regex Pattern: {0}\t{1}".format(
                key, val.pattern
            ))


class OP5DatabaseClass:
    def __init__(self, account, password, database, host):
        self.account = account
        self.password = password
        self.database = database
        self.host = host

        try:
            print("Starting database connection...")
            self.connection = psycopg2.connect(
                user=account,
                password=password,
                host=host,
                dbname=database,
                cursor_factory=RealDictCursor
            )
        except (Exception, psycopg2.DatabaseError) as error:
            print(error)

    def __del__(self):
        self.connection.close()

    def close(self):
        self.connection.close()
        print("Closing database connection.")

    def metadata_insert(self, entry_type, data):
        sql_insert_statement = """
        INSERT INTO metadata(entry_type, data)
        VALUES(%s, %s) ON CONFLICT DO NOTHING;
        """
        self.cursor = self.connection.cursor()
        self.cursor.execute(sql_insert_statement, (entry_type, data))
        self.connection.commit()
        self.cursor.close()

    def content_insert(self, filehash, override, item):
        sql_insert_statement = """
        INSERT INTO content(
                       filehash,
                       filename,
                       block_num,
                       block_type,
                       block_name,
                       override,
                       template,
                       content
                    )
        VALUES(%s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT DO NOTHING;
        """

        cursor = self.connection.cursor()
        cursor.execute(
            sql_insert_statement,
            (
                filehash,
                item['filename'],
                item['block_num'],
                item['type'],
                item['name'],
                override,
                item['template'],
                json.dumps(item['content']),
            )
        )
        self.connection.commit()
        cursor.close()

    def content_fetch(self, column_names, where_clause):
        sql_select_statement = """
        SELECT
            {0}
        FROM
            content
        WHERE
            {1}
        """.format(column_names, where_clause)

        cursor = self.connection.cursor()
        cursor.execute(sql_select_statement)
        rows = cursor.fetchall()
        cursor.close()
        return rows


def regex_match(regex, string):
    if regex.match(string):
        return True
    else:
        return False


def entry_cleaner(config_class, block_type, template, line):
    if block_type == 'contact':
        if config_class.replacements['common']['notification_cmds'].match(line):
            line = line.replace('commands', 'cmds')
        elif config_class.replacements['common']['template'].match(line):
            line = line.replace('use', 'template')

    elif block_type == 'host':
        if config_class.replacements['host']['failure_prediction'].match(line):
            line = None
        elif config_class.replacements['common']['template'].match(line):
            line = line.replace('use', 'template')

    elif block_type == 'service':
        if config_class.replacements['common']['template'].match(line):
            line = line.replace('use', 'template')

    # Breaking the line up into fields for JSON key/value pairs.
    if line:
        if block_type == 'timeperiod' \
           and not config_class.replacements['timeperiod']['nottimerange'].match(line):
            line = line.rsplit( ' ', 1)
        else:
            line = line.split(' ', 1)

        if len(line) == 1:
            line.append('')

    return line


def block_cleaner(block_type, parsed_block):
    if block_type == "contact":
        if "alias" not in parsed_block["content"] \
           and parsed_block["template"] == False:
            parsed_block["content"]["alias"] = \
                                        parsed_block["content"]["contact_name"]

        if "contactgroups" in parsed_block["content"]:
            if "," in parsed_block["content"]["contactgroups"]:
                parsed_block["content"]["contactgroups"] = \
                            parsed_block["content"]["contactgroups"].split(",")

            if parsed_block["content"]["contactgroups"] is "null":
                parsed_block["content"].pop("contactgroups")

    elif block_type == "contactgroup":
        # TODO Change this part to a regex function.
        # Making sure the members are a ", " separated list as the API
        # thinks a "," separated list is a single word.
        if "members" in parsed_block["content"] \
           and parsed_block["template"] == False:
            if "," in parsed_block["content"]["members"]:
                temp_list = list()
                for entry in parsed_block["content"]["members"].split(","):
                    temp_list.append(entry.strip())
                    parsed_block["content"]["members"] = temp_list

        if "alias" not in parsed_block["content"] \
           and parsed_block["template"] == False:
            parsed_block["content"]["alias"] = \
                                parsed_block["content"]["contactgroup_name"]

    elif block_type == "host":
        if "contact_groups" in parsed_block["content"]:
            parsed_block["content"]["contact_groups"] = \
                        parsed_block["content"]["contact_groups"].split(",")

        if "contacts" in parsed_block["content"]:
            if "," in parsed_block["content"]["contacts"]:
                parsed_block["content"]["contacts"] = \
                                parsed_block["content"]["contacts"].split(",")

        if "hostgroups" in parsed_block["content"]:
            parsed_block["content"]["hostgroups"] = \
                            parsed_block["content"]["hostgroups"].split(",")

    elif block_type == "hostgroup":
        if "members" in parsed_block["content"]:
            parsed_block["content"]["members"] = \
                               parsed_block["content"]["members"].split(',')

        if "hostgroup_name" not in parsed_block["content"] \
           and "alias" in parsed_block["content"]:
            parsed_block["content"]["hostgroup_name"] = \
                  parsed_block["content"]["alias"].lower().replace(" ", "-")

        if "hostgroup_members" in parsed_block["content"]:
            parsed_block["content"]["hostgroup_members"] = \
                        parsed_block["content"]["hostgroup_members"].split(",")

    elif block_type == "service":
        if "contact_groups" in parsed_block["content"]:
            parsed_block["content"]["contact_groups"] = \
                        parsed_block["content"]["contact_groups"].split(",")

        if parsed_block["template"] == False \
           and "service_description" in parsed_block["content"] \
           and "name" in parsed_block["content"]:
            parsed_block["content"]["display_name"] = \
                          parsed_block["content"].pop("name")
        elif "name" in parsed_block["content"] \
             and "service_description" not in parsed_block["content"] \
             and parsed_block["template"] == False:
            parsed_block["content"]["service_description"] = \
                                         parsed_block["content"].pop("name")

        if "service_description" not in parsed_block["content"] \
           and parsed_block["template"] == False:
            parsed_block["content"]["service_description"] = \
                                        parsed_block["content"]["host_name"]

        if parsed_block["template"] == True \
           and "service_description" in parsed_block["content"]:
            parsed_block["content"]["display_name"] = \
                          parsed_block["content"].pop("service_description")

        if "check_command" in parsed_block["content"] \
           and '!' in parsed_block["content"]["check_command"]:
            parsed_block["content"]["check_command"], \
                parsed_block["content"]["check_command_args"] = \
                parsed_block["content"]["check_command"].split("!", 1)

    elif block_type == "hostescalation":
        if "contact_groups" in parsed_block["content"] \
           and parsed_block["template"] == False:
            parsed_block["content"]["contact_groups"] = \
                        parsed_block["content"]["contact_groups"].split(',')

    elif block_type == "serviceescalation":
        if "contact_groups" in parsed_block["content"] \
           and parsed_block["template"] == False:
            parsed_block["content"]["contact_groups"] = \
                        parsed_block["content"]["contact_groups"].split(",")

    return parsed_block

def parse_file(file_obj, config_class, verbose=False):
    logger = logging.getLogger(__name__)
    in_block = False
    return_list = list()
    parsed_file = dict()
    block_num = 0
    block_type = None

    command_line_regex = re.compile("^command_line\s")

    for line in file_obj:
        line = line.strip()
        # Yes, lines could be tab separated. :(
        line = line.replace('\t', ' ')
        # Stripping out comments, because Monitor acts like they are part of
        # the name.
        if not command_line_regex.match(line):
            # TODO: Move this to regex capture groups.
            line = line.split(';', 1).pop(0).strip()

        if verbose:
            print("File line: {0}".format(line))
        if config_class.common['comment'].match(line) \
           or config_class.common['blankline'].match(line) \
           or config_class.common['script'].match(line):
            continue

        if not in_block:
            if config_class.common["block_start"].match(line):
                in_block = True

                parsed_file["filename"] = file_obj.name
                parsed_file["block_num"] = block_num
                parsed_file["type"] = ''
                parsed_file["name"] = ''
                parsed_file["template"] = False
                parsed_file["content"] = dict()

                for key in config_class.block.keys():
                    if config_class.block[key].match(line):
                        parsed_file["type"] = key
                        block_type = key
                        # Exiting for loop once we get a match because a block
                        # will only match once
                        break
        else:
            if config_class.common["block_end"].match(line):
                in_block = False
                block_num += 1
                parsed_file = block_cleaner(block_type, parsed_file)
                return_list.append(parsed_file)
                parsed_file = dict()
                parsed_file["content"] = dict()
            else:
                if verbose:
                    print("Line: {0}".format(line))
                logger.info("Line: {0}".format(line))

                if config_class.field["template"].match(line):
                    parsed_file["template"] = True
                elif config_class.field["name"].match(line):
                        parsed_file["name"] = line.strip().split().pop()

                line = entry_cleaner(config_class,
                                     block_type,
                                     parsed_file["template"],
                                     line)

                if line:
                    parsed_file["content"][line[0].strip()] = line[1].strip()

    return return_list


def process_files(worklist,
                  config_class,
                  db_obj,
                  verbose=False):
    logger = logging.getLogger(__name__)
    read_block_size = 65536

    for workfile in worklist:
        print("{0}".format(workfile))
        logger.info("Working on file: {0}".format(workfile))

        override = regex_match(config_class.override_file, workfile)

        # Hashing file to get a unique way to id the file besides the name.
        file_hash = hashlib.sha1()
        with open(workfile, 'rb') as file_obj_bin:
            file_read_buffer = file_obj_bin.read(read_block_size)
            while len(file_read_buffer) > 0:
                file_hash.update(file_read_buffer)
                file_read_buffer = file_obj_bin.read()

        with open(workfile, 'r') as file_obj:
            parsed_file_list = parse_file(file_obj, config_class, verbose)
            for item in parsed_file_list:
                db_obj.metadata_insert('type', item['type'])
                db_obj.content_insert(file_hash.hexdigest(), override, item)


def setup_monitor(db, monitor):
    # TODO: Create a dependency graph for each type so most of this crap is
    # deprecated.
    # TODO: Get a list from Monitor for each type so we can skip loading items
    # which are already objects in Monitor.
    print("Setting up OP5 Monitor...")

    column_list = "filename, content, block_name, block_type"

    # Starting adding commands
    where_clause = " and ".join([
        "block_type = 'command'",
        "template = false",
        "override = false"
    ])
    rows = db.content_fetch(
        column_list,
        where_clause
    )
    if len(rows) > 0:
        monitor.post("command", rows)
    # Ending adding commands

    # Starting loading timeperiods
    where_clause = ' and '.join([
        "block_type = 'timeperiod'",
        "override = false",
        "template = true"
    ])
    rows = db.content_fetch(
        column_list,
        where_clause
    )
    if len(rows) > 0:
        monitor.post("timeperiod", rows)

    where_clause = ' and '.join([
        "block_type = 'timeperiod'",
        "override = false",
        "template = false"
    ])
    rows = db.content_fetch(
        column_list,
        where_clause
    )
    if len(rows) > 0:
        monitor.post("timeperiod", rows)

    rows = db.content_fetch(
        column_list,
        "block_type = 'timeperiod' and override = true and template = false"
    )
    if len(rows) > 0:
        monitor.post("timeperiod", rows)
    # Ending loading timeperiods

    # Starting loading contact templates
    # Getting the generic contact since everything depends on that.
    # TODO Fix this so "generic-contact" isn't hardcoded.
    where_clause = " and ".join([
        "block_type = 'contact'",
        "template = true",
        "override = false",
        "content @> '{ \"name\": \"generic-contact\" }'"
    ])
    rows = db.content_fetch(
        column_list,
        where_clause
    )
    if len(rows) > 0:
        monitor.save_internal = 1
        monitor.post("contact_template", rows)
        monitor.save_interval = 20

    # Getting the rest of the contact_template entries.
    where_clause = " and ".join([
        "block_type = 'contact'",
        "template = true",
        "override = false",
        "not content @> '{ \"name\": \"generic-contact\" }'"
    ])
    rows = db.content_fetch(
        column_list,
        where_clause
    )
    if len(rows) > 0:
        monitor.post("contact_template", rows)

    # Getting contact_template overrides.
    where_clause = " and ".join([
        "block_type = 'contact'",
        "template = true",
        "override = true"
    ])
    rows = db.content_fetch(
        column_list,
        where_clause
    )
    if len(rows) > 0:
        monitor.post("contact_template", rows)

    # Ending loading contact templates

    # Starting loading contacts
    where_clause = " and ".join([
        "block_type = 'contact'",
        "template = false",
        "override = false"
    ])
    rows = db.content_fetch(
        column_list,
        where_clause
    )
    if len(rows) > 0:
        monitor.post("contact", rows)

    # Ending loading contacts

    # Starting loading contact groups
    where_clause = " and ".join([
        "block_type = 'contactgroup'",
        "content @> '{ \"contactgroup_name\": \"BlackMesh\" }'"
    ])
    rows = db.content_fetch(
        column_list,
        where_clause
    )
    if len(rows) > 0:
        monitor.post("contactgroup", rows)

    where_clause = " and ".join([
        "block_type = 'contactgroup'",
        "not content @> '{ \"contactgroup_name\": \"BlackMesh\" }'"
    ])
    rows = db.content_fetch(
        column_list,
        where_clause
    )
    if len(rows) > 0:
        monitor.post("contactgroup", rows)

    # Ending loading contact groups

    # Starting loading host templates
    where_clause = " and ".join([
        "block_type = 'host'",
        "template = true",
        "override = false",
        "content @> '{ \"name\": \"generic-host\" }'"
    ])
    rows = db.content_fetch(
        column_list,
        where_clause
    )
    if len(rows) > 0:
        monitor.save_interval = 1
        monitor.post("host_template", rows)
        monitor.save_interval = 20

    where_clause = " and ".join([
        "block_type = 'host'",
        "template = true",
        "override = false",
        "not content @> '{ \"name\": \"generic-host\" }'"
    ])
    rows = db.content_fetch(
        column_list,
        where_clause,
    )
    if len(rows) > 0:
        monitor.post("host_template", rows)

    # Ending loading host templates

    # Starting loading hostgroups templates
    where_clause = " and ".join([
        "block_type = 'hostgroup'",
        "template = true",
        "override = false",
    ])
    rows = db.content_fetch(
        column_list,
        where_clause
    )
    if len(rows) > 0:
        print("Adding hostgroup.")
        monitor.post("hostgroup", rows)

    # Ending loading hostgroups templates

    # Starting loading hostgroups without members
    where_clause = " and ".join([
        "block_type = 'hostgroup'",
        "template = false",
        "override = false",
        "not content ? 'members'"
    ])
    rows = db.content_fetch(
        column_list,
        where_clause
    )
    if len(rows) > 0:
        print("Adding hostgroup.")
        monitor.post("hostgroup", rows)

    # Ending loading hostgroups without members

    # Starting loading hosts
    # Parents first
    where_clause = " and ".join([
        "block_type = 'host'",
        "template = false",
        "override = false",
        "not content ? 'parents'"
    ])
    rows = db.content_fetch(
        column_list,
        where_clause
    )
    if len(rows) > 0:
        print("Adding host")
        monitor.post("host", rows)

    # Now children
    where_clause = " and ".join([
        "block_type = 'host'",
        "template = false",
        "override = false",
        "content ? 'parents'"
    ])
    rows = db.content_fetch(
        column_list,
        where_clause
    )
    # Looping through the hosts multiple times because my code to sort this out
    # is wonky, and I needed an immediate fix.
    if len(rows) > 0:
        print("Adding host 1st loop")
        monitor.post("host", rows)

    if len(rows) > 0:
        print("Adding host 2nd loop")
        monitor.post("host", rows)

    if len(rows) > 0:
        print("Adding host 3rd loop")
        monitor.post("host", rows)

    if len(rows) > 0:
        print("Adding host 4th loop")
        monitor.post("host", rows)

    # Ending loading hosts

    # Starting loading hostgroups with members
    where_clause = " and ".join([
        "block_type = 'hostgroup'",
        "template = false",
        "override = false",
        "content ? 'members'"
    ])
    rows = db.content_fetch(
        column_list,
        where_clause
    )
    if len(rows) > 0:
        print("Adding hostgroup.")
        monitor.post("hostgroup", rows)

    # Ending loading hostgroups with members

    # Starting loading base service template
    where_clause = " and ".join([
        "block_type = 'service'",
        "template = true",
        "override = false",
        "not content ? 'template'"
    ])
    rows = db.content_fetch(
        column_list,
        where_clause
    )
    if len(rows) > 0:
        print ("Adding service")
        monitor.post("service_template", rows)

    # Ending loading base service templates

    # Start loading servicegroup
    where_clause = " and ".join([
        "block_type = 'servicegroup'",
    ])
    rows = db.content_fetch(
        column_list,
        where_clause
    )
    if len(rows) > 0:
        print("Adding servicegroup")
        monitor.post("servicegroup", rows)
    # Ending loading servicegroups

    # Starting loading service templates
    where_clause = " and ".join([
        "block_type = 'service'",
        "content @> '{ \"name\": \"remote-service\"}'"
    ])
    rows = db.content_fetch(
        column_list,
        where_clause
    )
    if len(rows) > 0:
        print ("Adding service")
        monitor.post("service_template", rows)

    # Ending loading service templates

    # Starting loading service templates with servicegroup
    where_clause = " and ".join([
        "block_type = 'service'",
        "template = true",
        "content ? 'servicegroups'"
    ])
    rows = db.content_fetch(
        column_list,
        where_clause,
    )
    if len(rows) > 0:
        print("Adding service template with servicegroup dependencies")
        monitor.post("service_template", rows)

    # Ending loading service templates with servicegroup

    # Starting loading service templates without servicegroup
    where_clause = " and ".join([
        "block_type = 'service'",
        "template = true",
        "not content ? 'servicegroups'"
    ])
    rows = db.content_fetch(
        column_list,
        where_clause,
    )
    if len(rows) > 0:
        print("Adding service template without servicegroup dependencies")
        monitor.post("service_template", rows)
    # Ending loading service templates without servicegroup

    # Starting loading services
    where_clause = " and ".join([
        "block_type = 'service'",
        "template = false",
        "override = false",
    ])
    rows = db.content_fetch(
        column_list,
        where_clause
    )
    if len(rows) > 0:
        print("Adding service")
        monitor.post("service", rows)

    # Ending loading services


def main():
    description = "Walks a directory and consolidates config files"
    log_entry_format = ":".join(
        [
            '%(asctime)s',
            '%(levelname)s',
            '%(name)s',
            '%(message)s'
        ]
    )

    logging.basicConfig(
        format=log_entry_format,
        level=logging.INFO,
        filename="consolidation.log"
    )
    logger = logging.getLogger(__name__)

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "config",
        help="YAML formatted configuration file."
    )
    parser.add_argument(
        "url",
        help="OP5 Monitor server URL."
    )
    parser.add_argument(
        "account",
        help="OP5 Monitor account."
    )
    parser.add_argument(
        "password",
        help="OP5 Monitor account password."
    )
    parser.add_argument(
        "path",
        nargs='+',
        help="Space separated list of paths to search."
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action='store_true',
        help="Enable more output."
    )
    parser.add_argument(
        "--nossl",
        action='store_true',
        help="Disable SSL checks."
    )
    parser.add_argument(
        "--nop",
        action='store_true',
        help="Dry run, no operations are executed."
    )
    parser.add_argument(
        "--pop",
        action='store_true',
        help="Partial operations, don't save anything."
    )
    parser.add_argument(
        "-i",
        "--save-interval",
        type=int,
        default=20,
        dest="save_interval",
        help="Sets the interval between saves."
    )
    parser.add_argument(
        "-s",
        "--skip-load",
        dest='skip_load',
        action="store_true",
        help="Skips loading the files into the database. Database needs to populated for this to work."
    )
    args = parser.parse_args()

    op5monitor = OP5MonitorHTTP(
        args.url,
        args.account,
        args.password,
        args.save_interval
    )

    if args.nossl:
        op5monitor.disable_ssl()

    if args.nop:
        op5monitor.set_no_op()
    elif args.pop:
        op5monitor.set_part_op()

    config = ConfigParser.ConfigParser()
    config.read(args.config)

    ignore_dirs = config.get("ignore", "dirs")
    ignore_files = config.get("ignore", "files")
    include_file_ext_regex = ast.literal_eval(config.get("include",
                                                         "file_ext"))
    config_class = ConfigFileObj(config)
    config_class.print_common(verbose=args.verbose)
    config_class.print_block(verbose=args.verbose)
    config_class.print_fields(verbose=args.verbose)

    db_account = config.get("database", "account")
    db_password = config.get("database", "password")
    db_database = config.get("database", "database")
    db_host = config.get("database", "host")

    file_regex = list()
    file_work_list = list()
    # The length of the list changes as we delete items, so we have to delete
    # items in descending order to make sure the index number is correct and
    # valid. We're going to capture the index of items to delete here.
    index_list = list()

    for regex in include_file_ext_regex:
        file_regex.append(re.compile(regex))

    print("Starting work.")
    logging.info("Starting consolidation work.")

    for path in args.path:
        for root, dirlist, filelist in os.walk(path):
            logging.info("Root dir: {0}".format(root))
            for del_dir in ignore_dirs:
                if del_dir in dirlist:
                    idx = dirlist.index(del_dir)
                    if idx not in index_list:
                        logging.info("Ignoring dir: {0}".format(dirlist[idx]))
                        index_list.append(idx)

            # Sorting to make sure the list is in ascending order before we
            # start popping items off the end.
            index_list.sort()
            while index_list != []:
                del dirlist[index_list.pop()]

            for del_file in ignore_files:
                if del_file in filelist:
                    idx = filelist.index(del_file)
                    if idx not in index_list:
                        logging.info("Ignoring file: {0}".format(
                            filelist[idx])
                        )
                        index_list.append(idx)

            for file_name in filelist:
                for ext_regex in file_regex:
                    if not regex_match(ext_regex, file_name):
                        idx = filelist.index(file_name)
                        if idx not in index_list:
                            logging.info("Ignoring file: {0}".format(
                                filelist[idx]))
                            index_list.append(idx)
                    else:
                        break

            index_list.sort()
            while index_list != []:
                idx = index_list.pop()
                del filelist[idx]

            logging.info("File work list: {0}".format("; ".join(filelist)))

            for filename in filelist:
                file_full_name = "/".join([root, filename])
                file_work_list.append(file_full_name)

    db_obj = OP5DatabaseClass(
        db_account,
        db_password,
        db_database,
        db_host
    )
    if not args.skip_load:
        process_files(file_work_list, config_class, db_obj)
    else:
        logging.info("Skipping file loading. Database already populated... hopefully.")
        print("Skipping file loading. Database already populated... hopefully.")

    if not args.nop:
        setup_monitor(db_obj, op5monitor)
    else:
        print("No op set. Skipping loading into OP5 Monitor.")

    db_obj.close()

    print("Ending work.")
    logging.info("Ending consolidation work.")

    return 0


if __name__ == '__main__':
    main()
