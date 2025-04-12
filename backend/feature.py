#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import re

# Define a color scheme for different severity levels.
# Feel free to adjust these values or add more keys as needed.
COLORS = {
    "Critical": "\033[91m",  # Bright Red
    "High": "\033[93m",      # Bright Yellow
    "Medium": "\033[94m",    # Bright Blue
    "Low": "\033[92m",       # Bright Green
    "Reset": "\033[0m",
    "Bold": "\033[1m"
}

def nth_replace(string, old, new, n):
    """Replace the nth occurrence of old in string with new."""
    if string.count(old) >= n:
        left_join = old
        right_join = old
        groups = string.split(old)
        nth_split = [left_join.join(groups[:n]), right_join.join(groups[n:])]
        return new.join(nth_split)
    return string.replace(old, new)

def display(path, payload, vulnerability, line, declaration_text, declaration_line, colored, occurrence, plain, severity="Medium"):
    """
    Display detected vulnerability information with enhanced colored output.
    
    Parameters:
    - path: file path where vulnerability was found.
    - payload: list with vulnerability details (e.g. [function, vulnerability_type, protection_functions])
    - vulnerability: the matched vulnerability snippet.
    - line: line number where vulnerability was detected.
    - declaration_text: text of the variable declaration.
    - declaration_line: line number of the declaration.
    - colored: the vulnerable variable/code (used for highlighting).
    - occurrence: occurrence number of the vulnerability.
    - plain: if True, output is plain text (no colors).
    - severity: severity level ("Critical", "High", "Medium", "Low").
    """
    # Choose color codes if plain is not set.
    if not plain:
        severity_color = COLORS.get(severity, COLORS["Medium"])
        bold = COLORS["Bold"]
        reset = COLORS["Reset"]
    else:
        severity_color = ""
        bold = ""
        reset = ""
    
    # Header with severity color
    header = f"{bold}{severity_color}Potential vulnerability found: {payload[1]}{reset}" if not plain else f"Potential vulnerability found: {payload[1]}"
    
    # Display the line and file path where the vulnerability was found.
    line_str = f"-->{bold}{COLORS['Low'] if not plain else ''}{line}{reset} in {path}" if not plain else f"-->{line} in {path}"
    
    # Highlight the vulnerable code snippet.
    # Here we wrap the vulnerable code with the severity color.
    vuln_highlight = nth_replace("".join(vulnerability), colored, f"{severity_color}{colored}{reset}" if not plain else colored, occurrence)
    vuln_formatted = f"{payload[0]}({vuln_highlight})"
    
    # Print the vulnerability information.
    rows = 45
    columns = 190
    print("-" * (int(columns) - 1))
    print("Name        \t{}".format(header))
    print("-" * (int(columns) - 1))
    print(f"{bold}Line {reset}             {line_str}")
    print(f"{bold}Code {reset}             {vuln_formatted}")
    
    # Display declaration info if available.
    if "$_" not in colored:
        declared = "Undeclared in the file"
        if declaration_text != "":
            declared = f"Line n°{bold}{COLORS['Low'] if not plain else ''}{declaration_line}{reset} : {declaration_text}"
        print(f"{bold}Declaration {reset}      {declared}")
    print("")

def find_line_vuln(payload, vulnerability, content):
    """Find the line number of the vulnerability."""
    content = content.split('\n')
    for i in range(len(content)):
        if payload[0] + '(' + vulnerability[0] + vulnerability[1] + vulnerability[2] + ')' in content[i]:
            return str(i - 1)
    return "-1"

def find_line_declaration(declaration, content):
    """Find the line number where the variable is declared."""
    content = content.split('\n')
    for i in range(len(content)):
        if declaration in content[i]:
            return str(i)
    return "-1"

def clean_source_and_format(content):
    """Clean and format source code for analysis."""
    content = content.replace("    ", " ")  # Replace tabs with spaces.
    content = content.replace("echo ", "echo(").replace(";", ");")  # Normalize echo statements.
    return content

def check_protection(payload, match):
    """Check if a match contains protection."""
    for protection in payload:
        if protection in "".join(match):
            return True
    return False

def check_exception(match):
    """Check if match is an exception."""
    exceptions = ["_GET", "_REQUEST", "_POST", "_COOKIES", "_FILES"]
    for exception in exceptions:
        if exception in match:
            return True
    return False

def check_declaration(content, vuln, path):
    """Analyze and check variable declaration for vulnerabilities.
    Process include statements and append their content for analysis."""
    regex_declaration = re.compile("(include.*?|require.*?)\\([\"\'](.*?)[\"\']\\)")
    includes = regex_declaration.findall(content)
    for include in includes:
        relative_include = os.path.dirname(path) + "/"
        try:
            path_include = relative_include + include[1]
            with open(path_include, 'r') as f:
                content = f.read() + content
        except Exception as e:
            return False, "", ""
    
    # Look for declarations and reassess for vulnerabilities.
    vulnerability = vuln[1:].replace(')', '\\)').replace('(', '\\(')
    regex_declaration2 = re.compile("\\$(.*?)([\t ]*)as(?!=)([\t ]*)\\$" + vulnerability)
    declaration2 = regex_declaration2.findall(content)
    if len(declaration2) > 0:
        return check_declaration(content, "$" + declaration2[0][0], path)
    
    regex_declaration = re.compile("\\$" + vulnerability + "([\t ]*)=(?!=)(.*)")
    declaration = regex_declaration.findall(content)
    if len(declaration) > 0:
        declaration_text = "$" + vulnerability + declaration[0][0] + "=" + declaration[0][1]
        line_declaration = find_line_declaration(declaration_text, content)
        regex_constant = re.compile("\\$" + vuln[1:] + "([\t ]*)=[\t ]*?([\"\'(]*?[a-zA-Z0-9{}_\\(\\)@\\.,!: ]*?[\"\')]*?);")
        false_positive = regex_constant.match(declaration_text)
        if false_positive:
            return True, "", ""
        return False, declaration_text, line_declaration
    
    return False, "", ""