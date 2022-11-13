#!/usr/bin/python

"""RaceX

PHP XDebug Analyzer that checks potential PDO race condition

Usage:
    ./python main.py -f <xdebug_log.txt>

Author:
    Felix Halim - felix.halim@outlook.com

Version:
    1.0 - 13 November 2022
"""

__author__ = "Felix Halim"
__version__ = "1.0"
__email__ = "felix.halim@outlook.com"

import argparse
import re

EXECUTION_INDICATOR = ["->prepare"]
SQL_CRUD = ["CREATE", "INSERT", "UPDATE", "DELETE", "SELECT", "ALTER", "DROP"]
TABLE_INDICATOR = ["FROM", "UPDATE", "INTO", "TABLE", "JOIN"]
HEADER = "\033[95m"
BLUE = "\033[94m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
FAIL = "\033[91m"
ENDC = "\033[0m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"


def read_file(file_name):
    """Reads input file

    Args:
        file_name (str): the input file e.g.: index.php

    Returns:
        list: a list of strings representing the file source code
    """
    with open(file_name) as f:
        lines = f.readlines()
    return lines


def print_welcome_banner():
    welcome_banner = """
     _____            _____ ________   __ __      ____   ___  
    |  __ \     /\   / ____|  ____\ \ / / \ \    / /_ | / _ \ 
    | |__) |   /  \ | |    | |__   \ V /   \ \  / / | || | | |
    |  _  /   / /\ \| |    |  __|   > <     \ \/ /  | || | | |
    | | \ \  / ____ \ |____| |____ / . \     \  /   | || |_| |
    |_|  \_\/_/    \_\_____|______/_/ \_\     \/    |_(_)___/                                                                                 
    """
    print(f"{GREEN}{welcome_banner}{ENDC}\n")


def print_farewell_banner():
    print(f"{GREEN}# # # THANK YOU FOR USING - RaceX V1.0 # # #{ENDC}")


def contain_exe_indicator(code_statement):
    """Checks if a code statement contains SQL execution keyword via regex

    Args:
        code_statement (str): code statement to be checked

    Returns:
        list: a list of regex hit i.e. containing SQL execution keyword
    """
    regex_pattern = f"({'|'.join(EXECUTION_INDICATOR)})"
    regex = re.compile(regex_pattern)
    matches = regex.findall(code_statement)
    return matches


def parse_traces(log):
    """Parses traces detected in Xdebug log file into list

    Args:
        log (list): a list of string representing the Xdebug log

    Returns:
        list: a list of list that represents Xdebug log splitted by trace
    """
    traces = []
    trace = []
    for l in log:
        if "TRACE END" in l:
            traces.append(trace)
            trace = []
        elif contain_exe_indicator(l):
            prepare_statement = re.split("->", l)[2]
            trace.append(prepare_statement)
    return traces


def extract_table(sql):
    """Extracts SQL table(s) name detected in a SQL statement

    Args:
        sql (str): a string representing the SQL statement

    Returns:
        list: a unique list of string that represents SQL table name
    """
    tables = []
    for indicator in TABLE_INDICATOR:
        if indicator in sql:
            tables.append(re.split(';| |"', sql.split(indicator)[1].strip())[0])
    return list(set(tables))


def analyze_traces(traces, tables):
    """Categorizes traces by table name

    Args:
        traces (list): a list of list that represents Xdebug log splitted by trace
        tables (list): a unique list of string that represents SQL table name

    Returns:
        dict: a dictionary of table name as key and traces as value
    """
    trace_results = {table: [] for table in tables}
    for trace in traces:
        trace_result = {table: [] for table in tables}
        for line in trace:
            for t in extract_table(line):
                trace_result[t].append(line)
        for t, v in trace_result.items():
            trace_results[t].append(v)
    return trace_results


def print_traces(traces, summary=False):
    """Prints traces in a readable format

    Args:
        traces (list): a list of list that represents Xdebug log splitted by trace
        summary (str): a flag indicating whether min version is desired
    """
    if summary == "-min":
        summary = True
    for i, t in enumerate(traces):
        print(f"{BLUE}- Path[{i+1}]{ENDC}")
        for i, path in enumerate(t):
            clean_path = path.strip().rsplit(" ", 1)
            execution_statement = clean_path[0]
            filename_linenumber = clean_path[1].split(":")
            filename = filename_linenumber[0]
            linenumber = filename_linenumber[1]
            if summary:
                print(
                    f"  {YELLOW}{filename}{ENDC}:{BOLD}{linenumber}{ENDC}",
                    end="",
                )
                if i != len(t) - 1:
                    print(f"{CYAN}  ->{ENDC}", end="")
                else:
                    print("")
            else:
                print(
                    f"  - {execution_statement} {YELLOW}{filename}{ENDC}:{BOLD}{linenumber}{ENDC}"
                )
        print("")


def flatten(l):
    """Flattens list of list

    Args:
        l (list): list of list to be flattened

    Returns:
        list: flattened list of list
    """
    return [item for sublist in l for item in sublist]


def unique_lol(list_of_list):
    """Uniquifies list of list

    Args:
        list_of_list (list): list of list to be uniquify

    Returns:
        list: uniquified list of list
    """
    return [list(elem) for elem in set(tuple(l) for l in list_of_list)]


def analyze(traces):
    print(f"{GREEN}[*] Basic Info {ENDC}")
    print(f"{CYAN}Table(s) Detected{ENDC}")
    tables = set(flatten([extract_table(l) for t in traces for l in t]))
    for i, table in enumerate(tables):
        print(f"({i+1}). {table}")
    print("")

    trace_results = analyze_traces(traces, tables)

    print(f"{GREEN}[*] Potential Path(s) detected{ENDC}")
    for table, traces in trace_results.items():
        print(f"{CYAN}Table({table}):{ENDC}")
        traces = unique_lol(traces)
        print_traces(traces)

    print(f"{GREEN}[*] Path(s) Summary{ENDC}")
    for table, traces in trace_results.items():
        print(f"{CYAN}Table({table}):{ENDC}")
        traces = unique_lol(traces)
        print_traces(traces, "-min")


def main(args):
    print_welcome_banner()
    log = read_file(args.f)
    traces = parse_traces(log)
    unique_traces = unique_lol(traces)
    analyze(unique_traces)

    print_farewell_banner()


if __name__ == "__main__":
    """This is executed when run from the command line"""
    parser = argparse.ArgumentParser()

    parser.add_argument("-f", type=str, required=True)

    args = parser.parse_args()
    main(args)
