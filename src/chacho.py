import argparse
parser = argparse.ArgumentParser()
parser.add_argument('-p', '--path',
			required=True,
			action='store',
			dest='path',
			help='Path to directory where files to be organized are located')
parser.add_argument('-r', '--rules',
			required=True,
			action='store',
                        dest='rules_config',
			help='Path to configuration file where rules are defined')
args = parser.parse_args()
path = args.path
rules_config = args.rules_config

from os import listdir #List contents of a directory
import os
from stat import *
import shutil
import time
import datetime
import re
from enum import Enum
import sys

class LineType(Enum):
    START_RULE = 0
    FIELD = 1
    END_RULE = 2
    INVALID = 3
    COMMENT = 4


def line_parser(line):
    field = None
    value = None
    line_type = LineType.INVALID
    line_type_re = {'start_rule_re' : '(rule(\s*{){0,1})',
                    'comment_re'    : '\s*(#).*',
                    'field_re'      : '(\w+)=[\"\']{0,1}((?:\w+\s{0,1})+)[\"\']{0,1}$',
                    'end_rule'      : '\s*(}){1}\s*'}
    l = line.strip()
    if len(l) != 0:

        # TODO: more ellegant way of doing this? Instead of nested if else

        prog = re.compile(line_type_re['comment_re'])
        r = prog.findall(l)
        if len(r) == 1:
            line_type = LineType.COMMENT
        else:
            prog = re.compile(line_type_re['start_rule_re'])
            r = prog.findall(l)
            if len(r) == 1:
                line_type = LineType.START_RULE
            else:
                prog = re.compile(line_type_re['end_rule'])
                r = prog.findall(l)
                if len(r) == 1:
                    line_type = LineType.END_RULE
                else:
                    prog = re.compile(line_type_re['field_re'])
                    r = prog.findall(l)
                    if len(r) == 1:
                        field = r[0][0]
                        value  = r[0][1]
                        line_type= LineType.FIELD

        parsed_line = {'field' : field,
                       'value' : value,
                       'line_type' : line_type}
        return parsed_line

def name_parser(name):
    return name

def target_parser(target):
    return target

def type_parser(type_str):
    """Parses the value associated to a "type" field and checks if it is correct"""
    parsed_type = "unknown"
    type_def = ['regex',
                'extension',
                'format']

    if type_str in type_def:
        parsed_type = type_str

    return parsed_type

def action_parser(action):
    parsed_action = "unknown"
    action_def = ['remove',
                  'move',
                  'ignore']

    if action in action_def:
        parsed_action = action

    return parsed_action

def parse_relational_operator(operator):
    relation_operators_def = ['smaller',
                              'smallereq',
                              'equal',
                              'biggereq',
                              'bigger']

    print(operator.lower())

    if operator.lower() in relation_operators_def:
        relational_operator = operator.lower()
    else:
        relational_operator = "unknown"

    return relational_operator

def convert_string_to_seconds(time_quantity):
    time_in_seconds = 0
    seconds = 0
    time_quantity_re = {'number_and_type_re' : '(\d+)(\w)'}

    prog = re.compile(time_quantity_re['number_and_type_re'])
    r = prog.findall(time_quantity)
    if len(r) >= 1:
        if r[0][1] == "Y":
            # TODO: leap year *shrugs*
            seconds = 365*24*60*60
        elif r[0][1] == "m":
            # TODO: all months 30 days?
            seconds = 30*24*60*60
        elif r[0][1] == "d":
            seconds = 24*60*60
        elif r[0][1] == "H":
            seconds = 60*60
        elif r[0][1] == "M":
            seconds = 60
        elif r[0][1] == "S":
            seconds = 1
        else:
            seconds = 0

    time_in_seconds = seconds * int(r[0][0])

    return time_in_seconds

def parse_time_properties(condition):
    total_time = 0
    time_properties_re = {'extract_time_re' : 'is\s+(\d\w+)',
                            'split_time_re'  : '(\d+\w)+?'}
    prog = re.compile(time_properties_re['extract_time_re'])
    r = prog.findall(condition)
    if len(r) >= 1:
        prog = re.compile(time_properties_re['split_time_re'])
        r = prog.findall(r[0])
        for time in r:
            total_time += convert_string_to_seconds(time)

    r = re.findall("\w+", condition)
    if len(r) >= 1:
        relational_operator = parse_relational_operator(r[3])
        parsed_condition = {'property1' : r[0].lower(),
                             'property2' : r[5].lower(),
                             'quantity'  : total_time,
                             'relational_operator' : relational_operator}

    return parsed_condition

def convert_string_to_bytes(size_quantity):
    size_in_bytes = 0
    n_bytes = 0
    size_quantity_re = {'number_and_type_re' : '(\d+)(\w+)'}

    prog = re.compile(size_quantity_re['number_and_type_re'])
    r = prog.findall(size_quantity)
    if len(r) >= 1:
        #TODO improvet this, do not multiply manually
        if r[0][1] == "TiB":
            s_bytes = 1024*1024*1024*1024
        elif r[0][1] == "GiB":
            s_bytes = 1024*1024*1024
        elif r[0][1] == "MiB":
            s_bytes = 1024*1024
        elif r[0][1] == "KiB":
            s_bytes = 1024
        elif r[0][1] == "B":
            s_bytes = 1
        else:
            s_bytes = 0

    size_in_bytes= s_bytes * int(r[0][0])

    return size_in_bytes

def parse_size_properties(condition):
    total_size = 0
    size_properties_re = {'extract_size_re' : 'than\s+(\d\w+)',
                            'split_size_re'  : '(\d+\w{1,3})+?'}
    prog = re.compile(size_properties_re['extract_size_re'])
    r = prog.findall(condition)
    if len(r) >= 1:
        prog = re.compile(size_properties_re['split_size_re'])
        r = prog.findall(r[0])
        for size in r:
            total_size += convert_string_to_bytes(size)

    r = re.findall("\w+", condition)
    if len(r) >= 1:
        relational_operator = parse_relational_operator(r[2])

        parsed_condition = {'quantity'  : total_size,
                             'relational_operator' : relational_operator}

    return parsed_condition

def condition_parser(condition):
    time_properties_def = ['metachange',
                        'modification',
                        'access',
                        'currentdate']
    size_properties_def = ['size']
    parsed_condition = None

    r = re.findall("\w+", condition)
    if len(r) > 0:
        if r[0].lower() in time_properties_def:
            parsed_condition = parse_time_properties(condition)
        elif r[0].lower() in size_properties_def:
            parsed_condition = parse_size_properties(condition)
        else:
            pass

    return parsed_condition

def config_parser(rules_file):
    defining_rule_flag = False

    line_number = 1
    rule_id = 0

    rule_list = [];
    new_rule = {    'id'   : rule_id,
                    'name' : None,
                    'target' : None,
                    'type'   : None,
                    'action' : None,
                    'condition_list' : []};
    try:
        f = open(rules_file)
        for line in f:
            if len(line.strip()) > 0:
                parsed_line =  line_parser(line)

                if parsed_line['line_type'] == LineType.START_RULE:
                        if defining_rule_flag == True:
                            print("Error, unfinished rule definition \
                                    (line", line_number + ")")
                            return
                        else:
                            defining_rule_flag = True
                elif parsed_line['line_type'] == LineType.END_RULE:
                        if defining_rule_flag == True:
                            defining_rule_flag = False
                            rule_list.append(new_rule)

                            print(new_rule)

                            rule_id += 1
                            new_rule = {    'id'   : rule_id,
                                            'name' : None,
                                            'target' : None,
                                            'type'   : None,
                                            'action' : None,
                                            'condition_list' : []};
                        else:
                            print("Error, unmatched '}' \
                                   (line", line_number + ")")
                            return

                elif parsed_line['line_type'] == LineType.FIELD:
                        if parsed_line['field'] == "name":
                            new_rule['name'] = name_parser(parsed_line['value'])
                        elif parsed_line['field'] == "target":
                            new_rule['target'] = target_parser(parsed_line['value'])
                        elif parsed_line['field'] == "type":
                            new_rule['type'] = type_parser(parsed_line['value'])
                        elif parsed_line['field'] == "action":
                            new_rule['action'] = action_parser(parsed_line['value'])
                        elif parsed_line['field'] == "condition":
                            new_rule['condition_list'].append(condition_parser(parsed_line['value']))
                line_number = line_number + 1
    except FileNotFoundError:
        print("Error, could not open file '", rules_parser, "'")

    return 0

def main():
    config_parser(rules_config)

if __name__ == '__main__':
        sys.exit(main())
