#!/usr/bin/env python
import re

def entry_cleaner(block_type, template, line):
    contact_notification_commands = re.compile(
        "^(host|service)_notification_commands(_args)?"
    )
    contact_use = re.compile("^use")
    host_failure_predict = re.compile("^failure_prediction_enabled")

    if block_type == 'contact':
        if contact_notification_commands.match(line):
            print("Line match commands!")
            line = line.replace("commands", "cmds")
        elif contact_use.match(line):
            print("Line match use!")
            line = line.replace("use", "template")
    elif block_type == 'contact_group':
        print("X")
    elif block_type == 'host':
        if host_failure_predict.match(line):
            print("Cleaning entry: {0}".format(line))
            print("Line match host prediction.")
            line = None

    return line


def main():
    template = True
    block_type = 'host'

    content = [
        "name generic-host",
        "register 0",
        "check_period 24x7",
        "check_command check-host-alive",
        "check_interval 7",
        "contact_groups BlackMesh",
        "retry_interval 1",
        "process_perf_data 1",
        "max_check_attempts 6",
        "notification_period 24x7",
        "notification_options d,u,r",
        "event_handler_enabled 1",
        "notification_interval 15",
        "notifications_enabled 1",
        "flap_detection_enabled 1",
        "retain_status_information 1",
        "failure_prediction_enabled 1",
        "retain_nonstatus_information 1"
    ]

    for line in content:
        line = entry_cleaner(block_type, template, line)
        print(line)

    return 0


if __name__ == '__main__':
    main()
