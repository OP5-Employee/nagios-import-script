#!/usr/bin/env python2.6

# Standard Lib Modules
import os
import logging
import argparse
import fnmatch
import re


def reset_content_block():
    return {"type": 'unknown', "content": {}}


def parse_file(file_obj, regex):
    print("Parsing file.")
    parsed_file = dict()
    block_num = 0
    in_block = False
    content_block = reset_content_block()

    for line in file_obj:
        # Yes, lines could be tab separated. :(
        line = line.strip().replace('\t', ' ')

        if regex["comment"].match(line) or regex["blankline"].match(line):
            continue

        if not in_block:
            if regex["host"].match(line):
                print("Host match. {0}".format(file_obj.name))
                content_block["type"] = "host"
                in_block = True
            elif regex["hostgroup"].match(line):
                print("Hostgroup match. {0}".format(file_obj.name))
                content_block["type"] = "hostgroup"
                in_block = True
            elif regex["hostdependency"].match(line):
                print("hostdependency match. {0}".format(file_obj.name))
                content_block["type"] = "hostdependency"
                in_block = True
            elif regex["hostescalation"].match(line):
                print("hostescalation match. {0}".format(file_obj.name))
                content_block["type"] = "hostescalation"
                in_block = True
            elif regex["hostextinfo"].match(line):
                print("hostextinfo match. {0}".format(file_obj.name))
                content_block["type"] = "hostextinfo"
                in_block = True
            elif regex["service"].match(line):
                print("Service match. {0}".format(file_obj.name))
                content_block["type"] = "service"
                in_block = True
            elif regex["servicegroup"].match(line):
                print("Servicegroup match. {0}".format(file_obj.name))
                content_block["type"] = "servicegroup"
                in_block = True
            elif regex["servicedependency"].match(line):
                print("servicedependency match. {0}".format(file_obj.name))
                content_block["type"] = "servicedependency"
                in_block = True
            elif regex["serviceescalation"].match(line):
                print("serviceescalation match. {0}".format(file_obj.name))
                content_block["type"] = "serviceescalation"
                in_block = True
            elif regex["serviceextinfo"].match(line):
                print("serviceextinfo match. {0}".format(file_obj.name))
                content_block["type"] = "serviceextinfo"
                in_block = True
            elif regex["contact"].match(line):
                print("contact match. {0}".format(file_obj.name))
                content_block["type"] = "contact"
                in_block = True
            elif regex["contactgroup"].match(line):
                print("contactgroup match. {0}".format(file_obj.name))
                content_block["type"] = "contactgroup"
                in_block = True
            elif regex["timeperiod"].match(line):
                print("timeperiod match. {0}".format(file_obj.name))
                content_block["type"] = "timeperiod"
                in_block = True
            elif regex["command"].match(line):
                print("command match. {0}".format(file_obj.name))
                content_block["type"] = "command"
                in_block = True
        elif in_block:
            if regex["end"].match(line):  # This is for files with multiple blocks.
                print("End of block.")
                # Added content_block to parsed_file
                parsed_file[block_num] = content_block
                block_num += 1
                in_block = False
                content_block = reset_content_block()
            else:
                line = line.split(' ', 1)
                print("Line: {0}".format(line))
                if len(line) == 1:
                    line.append('')
                content_block["content"][line[0]] = line[1].strip()

    return parsed_file


def merge_files(file1, file2):
    print("Merging files.")
    print("Parsed File 1: {0}".format(file1))
    print("Parsed File 2: {0}".format(file2))
    for block in file2:
        if block in file1:
            # Making the assumption the types are the same.
            for key in file2[block]["content"]:
                if key in file1[block]["content"]:
                    if file1[block]["content"][key] != file2[block]["content"][key]:
                        file1[block]["content"][key] = file2[block]["content"][key]
                    else:
                        file1[block]["content"][key] = file1[block]["content"][key]
                else:
                    file1[block]["content"][key] = file2[block]["content"][key]
        else:
            file1[block] = file2[block]

    print("Merged Files: {0}".format(file1))

    return file1


def set_dict_block(file_dict, file_name, block_type, block_num, block):
    key = "{0}::{1}_block:{2}".format(file_name, block_type, block_num)
    file_dict[key] = block
    return file_dict


# A class should be created to hold all of the file dictionaries
def file_walk(
    path,
    file_filter,
    regex,
    host_file={},
    hostgroup_file={},
    hostdependency_file={},
    hostescalation_file={},
    hostextinfo_file={},
    service_file={},
    servicegroup_file={},
    servicedependency_file={},
    serviceescalation_file={},
    serviceextinfo_file={},
    contact_file={},
    contactgroup_file={},
    timeperiod_file={},
    command_file={},
):
    for root, _, filelist in os.walk(path):
        for base_file_name in fnmatch.filter(filelist, file_filter):
            base_file_name = "/".join(
                [
                    root,
                    base_file_name
                ]
            )
            base_file = open(base_file_name, 'r')
            override_file_name = ".".join([base_file_name, "override"])
            # Possible race condition with this. A try/catch block with open
            # would be better, but I don't want to deal with that right now.
            if os.path.isfile(override_file_name):
                override_file = open(override_file_name, 'r')
                base_file_parsed = parse_file(base_file, regex)
                override_file_parsed = parse_file(override_file, regex)
                final_file = merge_files(base_file_parsed, override_file_parsed)
                override_file.close()
            else:
                final_file = parse_file(base_file, regex)

            print("Final file: {0}".format(final_file))
            base_file.close()

            for block_num in final_file:
                block_type = final_file[block_num]["type"]
                print("Adding {0} file.".format(block_type))
                if block_type == "host":
                    host_file = set_dict_block(host_file,
                                               base_file_name,
                                               block_type,
                                               block_num,
                                               final_file[block_num])
                elif block_type == "hostgroup":
                    hostgroup_file = set_dict_block(hostgroup_file,
                                                    base_file_name,
                                                    block_type,
                                                    block_num,
                                                    final_file[block_num])
                elif block_type == "hostdependency":
                    hostdependency_file = set_dict_block(hostdependency_file,
                                                         base_file_name,
                                                         block_type,
                                                         block_num,
                                                         final_file[block_num])
                elif block_type == "hostescalation":
                    hostescalation_file = set_dict_block(hostescalation_file,
                                                         base_file_name,
                                                         block_type,
                                                         block_num,
                                                         final_file[block_num])
                elif block_type == "hostextinfo":
                    hostextinfo_file = set_dict_block(hostextinfo_file,
                                                      base_file_name,
                                                      block_type,
                                                      block_num, final_file[block_num])
                elif block_type == "service":
                    service_file = set_dict_block(service_file,
                                                  base_file_name,
                                                  block_type,
                                                  block_num,
                                                  final_file[block_num])
                elif block_type == "servicegroup":
                    servicegroup_file = set_dict_block(servicegroup_file,
                                                       base_file_name,
                                                       block_type,
                                                       block_num,
                                                       final_file[block_num])
                elif block_type == "servicedependency":
                    servicedependency_file = set_dict_block(servicedependency_file,
                                                            base_file_name,
                                                            block_type,
                                                            block_num,
                                                            final_file[block_num])
                elif block_type == "serviceescalation":
                    serviceescalation_file = set_dict_block(serviceescalation_file,
                                                            base_file_name,
                                                            block_type,
                                                            block_num,
                                                            final_file[block_num])
                elif block_type == "serviceextinfo":
                    serviceextinfo_file = set_dict_block(serviceextinfo_file,
                                                         base_file_name,
                                                         block_type,
                                                         block_num,
                                                         final_file[block_num])
                elif block_type == "contact":
                    contact_file = set_dict_block(contact_file,
                                                  base_file_name,
                                                  block_type,
                                                  block_num,
                                                  final_file[block_num])
                elif block_type == "contactgroup":
                    contactgroup_file = set_dict_block(contactgroup_file,
                                                       base_file_name,
                                                       block_type,
                                                       block_num,
                                                       final_file[block_num])
                elif block_type == "timeperiod":
                    timeperiod_file = set_dict_block(timeperiod_file,
                                                     base_file_name,
                                                     block_type,
                                                     block_num,
                                                     final_file[block_num])
                elif block_type == "command":
                    command_file = set_dict_block(command_file,
                                                  base_file_name,
                                                  block_type,
                                                  block_num,
                                                  final_file[block_num])

    return host_file, hostgroup_file, hostdependency_file, \
        hostescalation_file, hostextinfo_file, service_file, \
        servicegroup_file, servicedependency_file, serviceescalation_file, \
        serviceextinfo_file, contact_file, contactgroup_file, \
        timeperiod_file, command_file


def build_config(cfg_file, cfg_data):
    for filename in cfg_data:
        cfg_file.write("# Start {0}\n".format(filename))
        cfg_file.write("define {0} {{\n".format(cfg_data[filename]["type"]))
        for key in cfg_data[filename]["content"]:
            cfg_file.write("    {0}    {1}\n".format(
                key,
                cfg_data[filename]["content"][key]
            ))
        cfg_file.write("}\n")
        cfg_file.write("# End {0}\n".format(filename))


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
        "path",
        nargs='+',
        help="List of paths to search."
    )
    parser.add_argument(
        "-f",
        "--filter",
        dest='file_filter',
        default='*.cfg',
        help="Set the search filter for files, default \"*\"."
    )
    parser.add_argument(
        "-a",
        "--append",
        default=False,
        action='store_true',
        help="Appends the files rather then overwriting."
    )
    parser.add_argument(
        "-d",
        "--db-dest",
        help="Sets the location of the json db file."
    )
    parser.add_argument(
        "-A",
        "--host-file",
        dest='host_file',
        default='hosts.cfg',
        help="Changes the hosts config file."
    )
    parser.add_argument(
        "-B",
        "--hostgroup-file",
        dest='hostgroup_file',
        default='hostgroups.cfg',
        help="Changes the hostgroups config file."
    )
    parser.add_argument(
        "-C",
        "--hostdependency-file",
        dest='hostdependency_file',
        default='hostdependencies.cfg',
        help="Changes the hostdependencies config file."
    )
    parser.add_argument(
        "-D",
        "--hostescalation-file",
        dest='hostescalation_file',
        default='hostescalations.cfg',
        help="Changes the hostescalations config file."
    )
    parser.add_argument(
        "-E",
        "--hostextinfo-file",
        dest='hostextinfo_file',
        default='hostextinfo.cfg',
        help="Changes the hostextinfo config file."
    )
    parser.add_argument(
        "-F",
        "--service-file",
        dest='service_file',
        default='services.cfg',
        help="Changes the services config file."
    )
    parser.add_argument(
        "-G",
        "--servicegroup-file",
        dest='servicegroup_file',
        default='servicegroups.cfg',
        help="Changes the servicegroups config file."
    )
    parser.add_argument(
        "-H",
        "--servicedependency-file",
        dest='servicedependency_file',
        default='servicedependencies.cfg',
        help="Changes the servicedependencies config file."
    )
    parser.add_argument(
        "-I",
        "--serviceescalation-file",
        dest='serviceescalation_file',
        default='serviceescalations.cfg',
        help="Changes the serviceescalations config file."
    )
    parser.add_argument(
        "-J",
        "--serviceextinfo-file",
        dest='serviceextinfo_file',
        default='serviceextinfo.cfg',
        help="Changes the serviceextinfs config file."
    )
    parser.add_argument(
        "-K",
        "--contact-file",
        dest='contact_file',
        default='contacts.cfg',
        help="Changes the contacts config file."
    )
    parser.add_argument(
        "-L",
        "--contactgroup-file",
        dest='contactgroup_file',
        default='contactgroups.cfg',
        help="Changes the contactgroups config file."
    )
    parser.add_argument(
        "-M",
        "--timeperiod-file",
        dest='timeperiod_file',
        default='timeperiods.cfg',
        help="Changes the timeperiods config file."
    )
    parser.add_argument(
        "-N",
        "--command-file",
        dest='command_file',
        default='commands.cfg',
        help="Changes the commands config file."
    )
    args = parser.parse_args()

    file_filter = args.file_filter
    host_file_name = args.host_file
    hostgroup_file_name = args.hostgroup_file
    hostdependency_file_name = args.hostdependency_file
    hostescalation_file_name = args.hostescalation_file
    hostextinfo_file_name = args.hostextinfo_file
    service_file_name = args.service_file
    servicegroup_file_name = args.servicegroup_file
    servicedependency_file_name = args.servicedependency_file
    serviceescalation_file_name = args.serviceescalation_file
    serviceextinfo_file_name = args.serviceextinfo_file
    contact_file_name = args.contact_file
    contactgroup_file_name = args.contactgroup_file
    timeperiod_file_name = args.timeperiod_file
    command_file_name = args.command_file
    if (args.append):
        open_mode = 'a'
    else:
        open_mode = 'w'

    # TODO: Move this into a yaml file to allow for custom configurations.
    # Keep some defaults like blankline and comment.
    regex_dict = {
        "host": re.compile("^define host( |){"),
        "hostgroup": re.compile("^define hostgroup( |){"),
        "hostdependency": re.compile("^define hostdependency( |){"),
        "hostescalation": re.compile("^define hostescalation( |){"),
        "hostextinfo": re.compile("^define hostextinfo( |){"),
        "service": re.compile("^define service( |){"),
        "servicegroup": re.compile("^define servicegroup( |){"),
        "servicedependency": re.compile("^define servicedependency( |){"),
        "serviceescalation": re.compile("^define serviceescalation( |){"),
        "serviceextinfo": re.compile("^define serviceextinfo( |){"),
        "contact": re.compile("^define contact( |){"),
        "contactgroup": re.compile("^define contactgroup( |){"),
        "timeperiod": re.compile("^define timeperiod( |){"),
        "command": re.compile("^define command( |){"),
        "end": re.compile("^}$"),
        "comment": re.compile("^#"),
        "blankline": re.compile("^\s*$"),
    }

    logger.info("Starting consolidation work.")

    for path in args.path:
        host_file_dict, \
            hostgroup_file_dict, \
            hostdependency_file_dict, \
            hostescalation_file_dict, \
            hostextinfo_file_dict, \
            service_file_dict, \
            servicegroup_file_dict, \
            servicedependency_file_dict, \
            serviceescalation_file_dict, \
            serviceextinfo_file_dict, \
            contact_file_dict, \
            contactgroup_file_dict, \
            timeperiod_file_dict, \
            command_file_dict \
            = file_walk(path, file_filter, regex_dict)

    # TODO: Turn this into a loop
    host_file_handler = open(host_file_name, open_mode)
    build_config(host_file_handler, host_file_dict)
    host_file_handler.close()

    hostgroup_file_handler = open(hostgroup_file_name, open_mode)
    build_config(hostgroup_file_handler, hostgroup_file_dict)
    hostgroup_file_handler.close()

    hostdependency_file_handler = open(hostdependency_file_name, open_mode)
    build_config(hostdependency_file_handler, hostdependency_file_dict)
    hostdependency_file_handler.close()

    hostescalation_file_handler = open(hostescalation_file_name, open_mode)
    build_config(hostescalation_file_handler, hostescalation_file_dict)
    hostescalation_file_handler.close()

    hostextinfo_file_handler = open(hostextinfo_file_name, open_mode)
    build_config(hostextinfo_file_handler, hostextinfo_file_dict)
    hostextinfo_file_handler.close()

    service_file_handler = open(service_file_name, open_mode)
    build_config(service_file_handler, service_file_dict)
    service_file_handler.close()

    servicegroup_file_handler = open(servicegroup_file_name, open_mode)
    build_config(servicegroup_file_handler, servicegroup_file_dict)
    servicegroup_file_handler.close()

    servicedependency_file_handler = open(servicedependency_file_name,
                                          open_mode)
    build_config(servicedependency_file_handler, servicedependency_file_dict)
    servicedependency_file_handler.close()

    serviceescalation_file_handler = open(serviceescalation_file_name,
                                          open_mode)
    build_config(serviceescalation_file_handler, serviceescalation_file_dict)
    serviceescalation_file_handler.close()

    serviceextinfo_file_handler = open(serviceextinfo_file_name, open_mode)
    build_config(serviceextinfo_file_handler, serviceextinfo_file_dict)
    serviceextinfo_file_handler.close()

    contact_file_handler = open(contact_file_name, open_mode)
    build_config(contact_file_handler, contact_file_dict)
    contact_file_handler.close()

    contactgroup_file_handler = open(contactgroup_file_name, open_mode)
    build_config(contactgroup_file_handler, contactgroup_file_dict)
    contactgroup_file_handler.close()

    timeperiod_file_handler = open(timeperiod_file_name, open_mode)
    build_config(timeperiod_file_handler, timeperiod_file_dict)
    timeperiod_file_handler.close()

    command_file_handler = open(command_file_name, open_mode)
    build_config(command_file_handler, command_file_dict)
    command_file_handler.close()

    return 0


if __name__ == '__main__':
    main()
