#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
detect.py

This module analyzes PHP source files to detect various security vulnerabilities.
It uses patterns and payloads defined in indicators.py, formatting and display utilities
from feature.py, and writes each detected vulnerability into a text report in the Report folder.
It also computes Shannon entropy to detect high-entropy strings, which may indicate sensitive data.
"""

import os
import re
import math
from indicators import *
from feature import *

# Global counters for reporting
result_count = 0
result_files = 0

# Ensure the Report folder exists to store vulnerability text files
REPORT_FOLDER = "Report"
if not os.path.exists(REPORT_FOLDER):
    os.makedirs(REPORT_FOLDER)

def shannon_entropy(data, iterator):
    """
    Calculates the Shannon entropy of a string. This metric is a measure of the unpredictability
    or randomness of the data, used to detect potentially sensitive information like passwords.
    
    Parameters:
    - data: The string to calculate entropy for.
    - iterator: A collection of unique characters to consider in the entropy calculation.
    
    Returns:
    - The Shannon entropy value as a float.
    """
    if not data:
        return 0
    entropy = 0
    for x in iterator:
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log(p_x, 2)
    return entropy

def analysis(path, plain):
    """
    Analyzes a single file's source code to identify security vulnerabilities.
    Writes details to a report file in the REPORT_FOLDER if a vulnerability is found.
    If none are found, creates a report file that says "No vulnerabilities detected."
    
    Parameters:
    - path: Path to the file to analyze.
    - plain: Boolean flag indicating whether output should be plain text.
    """
    global result_count, result_files
    result_files += 1

    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as content_file:
            content = content_file.read()
    except Exception as e:
        print(f"Error reading {path}: {e}")
        return

    # Clean the source code for improved detection.
    content = clean_source_and_format(content)

    # --- Detect Hardcoded Credentials ---
    credz = ['pass', 'secret', 'token', 'pwd', 'api-key']
    regex_var_detect = r"\$[\w\s]+\s?=\s?[\"|'].*[\"|']|define\([\"|'].*[\"|']\)"
    compiled_regex = re.compile(regex_var_detect, re.I)
    content_pure = content.replace(' ', '')
    matches = compiled_regex.findall(content_pure)
    
    for vuln_content in matches:
        for credential in credz:
            if credential in vuln_content.lower():
                payload = ["", "Hardcoded Credential", []]
                add_vuln_var(payload, plain, path, vuln_content, content, regex_var_detect)
                break

    # --- Detect High Entropy Strings ---
    regex_var_detect_entropy = r".*?=\s?[\"|'].*?[\"|'].*?"
    compiled_regex_entropy = re.compile(regex_var_detect_entropy, re.I)
    content_pure = content.replace(' ', '')
    matches = compiled_regex_entropy.findall(content_pure)
    BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    HEX_CHARS = "1234567890abcdefABCDEF"
    
    for vuln_content in matches:
        payload = ["", "High Entropy String", []]
        if (shannon_entropy(vuln_content, BASE64_CHARS) >= 4.1 or
            shannon_entropy(vuln_content, HEX_CHARS) >= 2.5):
            add_vuln_var(payload, plain, path, vuln_content, content, regex_var_detect_entropy)

    # --- Detect Other Vulnerabilities (RCE/SQLI/LFI/XSS, etc.) ---
    for payload in payloads:
        regex = re.compile(payload[0] + regex_indicators)
        matches = regex.findall(content.replace(" ", "(PLACEHOLDER"))
        for vuln_content in matches:
            vuln_content = list(vuln_content)
            for i in range(len(vuln_content)):
                vuln_content[i] = vuln_content[i].replace("(PLACEHOLDER", " ")
                vuln_content[i] = vuln_content[i].replace("PLACEHOLDER", "")
            occurence = 0
            if not check_protection(payload[2], vuln_content):
                declaration_text, line = "", ""
                sentence = "".join(vuln_content)
                regex_extract = re.compile(regex_indicators[2:-2])
                for vulnerable_var in regex_extract.findall(sentence):
                    false_positive = False
                    occurence += 1
                    if not check_exception(vulnerable_var[1]):
                        false_positive, declaration_text, line = check_declaration(content, vulnerable_var[1], path)
                        is_protected = check_protection(payload[2], declaration_text)
                        false_positive = is_protected if is_protected else false_positive
                    line_vuln = find_line_vuln(payload, vuln_content, content)
                    if "$_" not in vulnerable_var[1]:
                        if "$" not in declaration_text.replace(vulnerable_var[1], ''):
                            false_positive = True
                    if not false_positive:
                        result_count += 1
                        # Display to terminal
                        display(path, payload, vuln_content, line_vuln, declaration_text, line,
                                vulnerable_var[1], occurence, plain)
                        # Write to report file
                        add_vuln_var(payload, plain, path, vuln_content, content, regex_indicators, occurence)

    # After scanning, if no report file was written for this file, create one with a default message.
    report_file = os.path.join(REPORT_FOLDER, f"{os.path.basename(path)}.txt")
    if not os.path.exists(report_file):
        with open(report_file, "w", encoding="utf-8") as f:
            f.write("No vulnerabilities detected.\n")

def recursive(dir_path, progress, plain):
    """
    Recursively scans directories for PHP files and analyzes them for vulnerabilities.
    
    Parameters:
    - dir_path: The directory to start scanning from.
    - progress: The current depth of recursion, used for displaying progress.
    - plain: Indicates whether to use plain text for progress indicators.
    """
    progress += 1
    progress_indicator = '⬛' if not plain else "█"
    try:
        for name in os.listdir(dir_path):
            print('\tAnalyzing : ' + progress_indicator * progress + '\r', end="\r")
            full_path = os.path.join(dir_path, name)
            if os.path.isfile(full_path):
                if ".php" in full_path:
                    analysis(full_path, plain)
            else:
                recursive(full_path, progress, plain)
    except OSError as e:
        print("Error 404 - Not Found, maybe you need more rights? " + " " * 30)
        exit(-1)

def scanresults():
    """
    Prints a summary of the scan results, including the number of vulnerabilities found and the number of files analyzed.
    """
    global result_count, result_files
    print("Found {} vulnerabilities in {} files".format(result_count, result_files))

def add_vuln_var(payload, plain, path, vuln_content, page_content, regex_var_detect, occurence=1):
    """
    Adds a found vulnerability to the results, displays it, and writes it to a text file in the Report folder.
    ...
    """
    line_vuln = -1
    splitted_content = page_content.split('\n')
    compiled_regex = re.compile(regex_var_detect, re.I)
    for i, line in enumerate(splitted_content):
        if compiled_regex.findall(line):
            line_vuln = i
            break

    # Convert vuln_content to a string if it's a list
    vuln_str = "".join(vuln_content) if isinstance(vuln_content, list) else vuln_content

    # Display the vulnerability info on the console.
    display(path, payload, vuln_content, line_vuln, vuln_str, str(line_vuln), vuln_str, occurence, plain)

    # Write vulnerability info to a text file in the Report folder.
    base_name = os.path.basename(path)
    report_file = os.path.join(REPORT_FOLDER, f"{base_name}.txt")
    with open(report_file, "a", encoding="utf-8") as f:
        f.write("Name: " + payload[1] + "\n")
        f.write("File: " + path + "\n")
        f.write("Line: " + str(line_vuln) + "\n")
        f.write("Code: " + vuln_str + "\n")
        f.write("--------------------------------------------\n")

    global result_count
    result_count += 1