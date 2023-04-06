"""
merge_sysmon_configs.py

Disclaimer: The following script was generated using GPT-4 through chat.openai.com
    The conversation can be found here: https://gist.github.com/cnnrshd/7d76c2956cf0ff3f46e04f61f582af60
    Modifications past the initial commit are (likely) human - only modifications I've made are comments.

This script is used to merge multiple Sysmon configuration files based on their priority.
The highest priority is at the top.
It reads a list of configuration file paths and priorities from an input TSV, CSV, or JSON file.
The merged Sysmon configuration is printed to the console.

Usage:
    python merge_sysmon_configs.py <input_file> [-f/--format tsv/csv/json]

Arguments:
    input_file: Path to the TSV, CSV, or JSON file containing filepaths and priorities.
                The file should have two columns: "filepath" and "priority".
                Example:
                    file1.xml,1
                    file2.xml,10
                    file3.xml,1

    -f/--format: Optional flag to override file format detection.
                 Supported formats are tsv, csv, and json.

The script will merge the Sysmon configurations based on their type, subtype, and priority.
Configurations with the same type and subtype will be merged within the same heading.
Type refers to the Event Type (ProcessCreate, FileCreate), subtype referes to include/exclude
"""

import argparse
import json
import csv
import os
from pathlib import Path
from lxml import etree
from typing import List, Dict, Tuple, Union

def detect_file_format(file_path: str) -> str:
    """
    Detect file format based on file extension.

    Args:
        file_path: Path to the input file.

    Returns:
        Detected file format (tsv, csv, or json).
    """
    _, ext = os.path.splitext(file_path)
    file_format = ext[1:].lower()
    if file_format not in ["tsv", "csv", "json"]:
        raise ValueError("Unsupported file format")
    return file_format

def read_file_list(file_path: str, file_format: str) -> List[Dict[str, Union[str, int]]]:
    """
    Read a file containing filepaths and priorities in TSV, CSV, or JSON format.

    Args:
        file_path: Path to the input file.
        file_format: Format of the input file (tsv, csv, or json).

    Returns:
        A list of dictionaries containing filepaths and priorities.
    """
    file_list = []
    if file_format == "tsv":
        with open(file_path, "r") as file:
            reader = csv.DictReader(file, delimiter="\t")
            file_list = [row for row in reader]
    elif file_format == "csv":
        with open(file_path, "r") as file:
            reader = csv.DictReader(file)
            file_list = [row for row in reader]
    elif file_format == "json":
        with open(file_path, "r") as file:
            file_list = json.load(file)
    return file_list

def merge_sysmon_configs(file_list: List[Dict[str, Union[str, int]]]) -> etree.Element:
    """
    Merge Sysmon config files based on their type, subtype, and priority.

    Args:
        file_list: A list of dictionaries containing filepaths and priorities.

    Returns:
        An lxml.etree.Element representing the merged Sysmon configuration.
    """
    merged_sysmon = etree.Element("Sysmon")
    merged_event_filtering = etree.SubElement(merged_sysmon, "EventFiltering")
    event_dict: Dict[Tuple[str, str], etree.Element] = {}

    for file_info in sorted(file_list, key=lambda x: int(x["priority"])):
        file_path = file_info["filepath"]
        if Path(file_path).is_file():
            with open(file_path, "r") as file:
                tree = etree.parse(file)
                rule_group = tree.find(".//RuleGroup")
                for event in rule_group:
                    event_type = event.tag
                    onmatch = event.get("onmatch")
                    key = (event_type, onmatch)

                    if key not in event_dict:
                        event_dict[key] = event
                        merged_event_filtering.append(rule_group)
                    else:
                        for child in event:
                            event_dict[key].append(child)

    return merged_sysmon

def main() -> None:
    parser = argparse.ArgumentParser(description="Merge Sysmon config files")
    parser.add_argument("file", help="Path to the TSV, CSV, or JSON file containing filepaths and priorities")
    parser.add_argument("-f", "--format", choices=["tsv", "csv", "json"], help="Override file format detection")
    args = parser.parse_args()

    file_path = args.file

    try:
        if not args.format:
            file_format = detect_file_format(file_path)
        else:
            file_format = args.format
    except ValueError as e:
        print(f"Error: {e}")
        return

    try:
        file_list = read_file_list(file_path, file_format)
    except Exception as e:
        print(f"Error reading file list: {e}")
        return

    try:
        merged_sysmon = merge_sysmon_configs(file_list)
    except Exception as e:
        print(f"Error merging Sysmon configs: {e}")
        return

    print(etree.tostring(merged_sysmon, pretty_print=True).decode())

if __name__ == "__main__":
    main()
