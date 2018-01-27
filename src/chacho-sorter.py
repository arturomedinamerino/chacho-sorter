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
        parsed_condition = { 'type'      : 'time',
                             'property1' : r[0].lower(),
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

        parsed_condition = {'type'      : 'size',
                            'quantity'  : total_size,
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

    return rule_list


def get_current_time():
    """Obtain current system time in two formats: epoch and human-readable
    format"""

    current_time_epoch = time.time()
    current_time_date = datetime.datetime.fromtimestamp(current_time_epoch)

    sys_time = { 'epoch' : current_time_epoch,
                 'date'  : current_time_date}

    return sys_time

def search_rule(f_name, rule_list):
    found_rule = None
    for rule in rule_list:
        if rule['type'] == "regex":
            r = re.findall(rule['target'], f_name['name'])
        elif rule['type'] == "extension":
            r = re.findall(".*\." + rule['target'], f_name['name'])
        # TODO file format, as provided by the 'file' utility
        else:
            continue

        if len(r) == 1:
            found_rule = rule
            break
    return found_rule

def compare_two_quantities(q1, q2, quantity, relational_operator):
    """Compare two given quantities, q1 and q2, and determine if the difference
    between them is at least 'quantity'"""
    meets_condition = False
    if relational_operator == "smaller":
        if q1 < (q2 - quantity):
            meets_condition = True
    elif relational_operator == "smallereq":
        if q1 <= (q2 - quantity):
            meets_condition = True
    elif relational_operator == "equal":
        if q1 == q2:
            meets_condition = True
    elif relational_operator == "biggereq":
        if (q1 - quantity) >= q2:
            meets_condition = True
    elif relational_operator == "bigger":
        if (q1 - quantity) >= q2:
            meets_condition = True
    else:
        print("Unknown operator")
        #TODO raise an exception
        pass

    return meets_condition

def get_time_property(f_name, property_type):
    f_stat = os.stat(f_name['full_path'])

    sys_time = get_current_time()

    f_last_access_epoch = f_stat.st_atime
    f_last_metadata_epoch = f_stat.st_ctime
    f_last_content_epoch = f_stat.st_mtime


    if property_type == 'modification':
        p = f_last_metadata_epoch
    elif property_type == 'access':
        p = f_last_access_epoch
    elif property_type == 'metachange':
        p = f_last_metadata_epoch
    elif property_type == 'currentdate':
        p = sys_time['epoch']
    else:
        #TODO raise an exception
        pass


    return p

def check_time_condition(f_name, condition):
    meets_condition = False
    p1 = get_time_property(f_name, condition['property1'])
    p2 = get_time_property(f_name, condition['property2'])

    meets_condition = compare_two_quantities(p1,
                                             p2,
                                             condition['quantity'],
                                             condition['relational_operator'])

    return meets_condition

def check_size_condition(f_name, condition):
    meets_condition = False
    f_stat = os.stat(f_name['full_path'])
    f_size = f_stat.st_size

    meets_condition = compare_two_quantities(f_size,
                                             condition['quantity'],
                                             0,
                                             condition['relational_operator'])
    return meets_condition

def check_rule_conditions(f_name, rule):
    meets_all = True
    for condition in rule['condition_list']:
        if condition['type'] == 'size':
            meets_condition = check_size_condition(f_name, condition)

        elif condition['type'] == 'time':
            meets_condition = check_time_condition(f_name, condition)
        else:
            print("Unknown condition type")
            # TODO: rise an error
            continue

        meets_all = meets_all and meets_condition
        if meets_all == False:
            break

    return meets_all

def apply_rules(rule_list):

    for f in listdir(path):
        f_path = path +'/'+ f
        f_stat = os.stat(f_path)

        f_name = { 'name'      : f,
                   'full_path' : f_path}

        print("\nFile:", f + "...")
        if S_ISREG(f_stat.st_mode):
            print("Is a regular file")
            rule = search_rule(f_name, rule_list)
            if rule is not None:
                print("There are rule for this type of file")
                meets_all = check_rule_conditions(f_name, rule)
            else:
                continue

            if not os.path.exists(path + "/foo"):
                os.makedirs(path + "/foo")

            if meets_all == True:
                shutil.copy(f_name['full_path'], path + "/foo/" + f)

        elif S_ISDIR(f_stat.st_mode):
            print("Is a directory. Leave it alone")
        else:
            print("Is neither a regular file nor a directory. Should probably \
                    leave it alone")


def main():
    rule_list = config_parser(rules_config)
    apply_rules(rule_list)
    return 0

if __name__ == '__main__':
        sys.exit(main())
