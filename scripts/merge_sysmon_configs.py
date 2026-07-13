"""
merge_sysmon_configs.py

This script is used to merge multiple Sysmon configuration files based on their priority - highest at top.
It reads a list of configuration file paths and priorities from an input TSV, CSV, or JSON file.

Usage:
    python merge_sysmon_configs.py <input_file> [-f/--format tsv/csv/json] -b <template_file> -o <output_file>

Arguments:
    input_file: Path to the TSV, CSV, or JSON file containing filepaths and priorities.
                The file should have two columns: "filepath" and "priority".
                Example:
                    file1.xml,1
                    file2.xml,10
                    file3.xml,1

    -f/--format: Optional flag to override file format detection.
                 Supported formats are tsv, csv, and json.

    -o/--outfile:   Where to write the output to. Defaults to stdout.

    -b/--base-config:   A template config to insert compiled config into. See sysmon_template.xml.
                        This is also where banners can be modified.

The script will merge the Sysmon configurations based on their type, subtype, and priority.
Configurations with the same type and subtype will be merged within the same heading.
Type refers to the Event Type (ProcessCreate, FileCreate), subtype referes to include/exclude

Disclaimer: The following script was generated in part using GPT-4 through chat.openai.com
    Disclaimer is provided in accordance with OpenAI's Usage Policy and Terms of User
    The conversation can be found here: https://gist.github.com/cnnrshd/7d76c2956cf0ff3f46e04f61f582af60
"""

import argparse
import csv
import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Tuple, Union

from lxml import etree
from packaging.version import parse as vparse

logging.basicConfig(level=logging.INFO)

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
        logging.exception(f"Received file format {file_format}")
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
        logging.info(f"Reading file {file_path} as 'tsv'")
        with open(file_path, "r") as file:
            reader = csv.DictReader(file, delimiter="\t")
            file_list = [row for row in reader]
    elif file_format == "csv":
        logging.info(f"Reading file {file_path} as 'csv'")
        with open(file_path, "r") as file:
            reader = csv.DictReader(file)
            file_list = [row for row in reader]
    elif file_format == "json":
        logging.info(f"Reading file {file_path} as 'json'")
        with open(file_path, "r") as file:
            file_list = json.load(file)
    logging.info(f"Detected {len(file_list)} items in {file_path}")
    return file_list

def merge_sysmon_configs(file_list: List[Dict[str, Union[str, int]]], force_grouprelation_or : bool) -> etree.Element:
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
    versions_set = set()

    for file_info in sorted(file_list, key=lambda x: int(x["priority"]),reverse=True):
        logging.debug(f"Working with {file_info}")
        file_path = file_info["filepath"]
        if Path(file_path).is_file():
            tree = etree.parse(file_path,parser=etree.XMLParser(remove_blank_text=True))
            # grab schema version
            version = tree.getroot().get("schemaversion")
            try:
                versions_set.add(vparse(version))
            except Exception as e:
                logging.exception(f"Error parsing version {version} in file {file_path}, skipping file")
                continue
            rule_group = tree.find(".//RuleGroup")
            if force_grouprelation_or:
                rule_group.set("groupRelation","or")
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
        else:
            logging.warning(f"Provided invalid path {file_path}, will not be merged")

    versions_list = list(versions_set)
    versions_list.sort(reverse=True)
    logging.debug(f"Versions found across all files: {[str(vers) for vers in versions_list]}")
    merged_sysmon.set("schemaversion", str(versions_list[0]))

    return merged_sysmon

def merge_with_base_config(merged_sysmon: etree.Element, base_config_file: str) -> etree.Element:
    """
    Merge the base config with the merged Sysmon configurations.

    Args:
        merged_sysmon: Merged Sysmon configurations.
        base_config_file: Path to the base config file.

    Returns:
        Merged Sysmon configurations with the base config.
    """
    base_tree = etree.parse(base_config_file.name, parser=etree.XMLParser(remove_blank_text=True))
    base_root = base_tree.getroot()
    base_event_filtering = base_root.find("EventFiltering")

    if base_event_filtering is not None:
        base_root.remove(base_event_filtering)

    new_event_filtering = etree.Element("EventFiltering")
    for rule_group in merged_sysmon.findall("EventFiltering/RuleGroup"):
        new_event_filtering.append(rule_group)

    base_root.set("schemaversion",merged_sysmon.get("schemaversion"))

    base_root.append(new_event_filtering)

    return base_root

def main() -> None:
    parser = argparse.ArgumentParser(description="Merge Sysmon config files")
    parser.add_argument("file", type=argparse.FileType("r"), help="Path to the TSV, CSV, or JSON file containing filepaths and priorities")
    parser.add_argument("-f", "--format", choices=["tsv", "csv", "json"], help="Override file format detection")
    parser.add_argument("-o", "--outfile", type=argparse.FileType("w"), default="-", help="File to output to, defaults to stdout")
    parser.add_argument("-b", "--base-config", type=argparse.FileType("r"), help="Path to the base config file with top-level Sysmon elements")
    parser.add_argument("--debug", action="store_true", default=False, help="Enable debug logging")
    parser.add_argument("--no-force-grouprelation-or", dest="force_grouprelation_or", action="store_false", default=True, help="Disable forcing groupRelation attribute for rules to 'or' (default: force to 'or')")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    file_path = args.file.name

    try:
        if not args.format:
            file_format = detect_file_format(file_path)
        else:
            file_format = args.format
    except ValueError as e:
        logging.exception(f"Error with file type: {e}")
        exit(1)

    try:
        file_list = read_file_list(file_path, file_format)
    except Exception as e:
        logging.exception(f"Error reading file list: {e}")
        exit(1)

    try:
        merged_sysmon = merge_sysmon_configs(file_list, args.force_grouprelation_or)
        if args.base_config:
            merged_sysmon = merge_with_base_config(merged_sysmon, args.base_config)
    except TypeError as e:
        logging.exception(f"Likely missing a priority in config list: {e}")
        exit(1)
    except Exception as e:
        logging.exception(f"Error merging Sysmon configs: {e}")
        exit(1)

    args.outfile.write(etree.tostring(merged_sysmon, pretty_print=True).decode())

if __name__ == "__main__":
    main()
