#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import re

def nth_replace(string, old, new, n):
    """Replace the nth occurrence of old in string with new."""
    if string.count(old) >= n:
        left_join = old
        right_join = old
        groups = string.split(old)
        nth_split = [left_join.join(groups[:n]), right_join.join(groups[n:])]
        return new.join(nth_split)
    return string.replace(old, new)


def display(path, payload, vulnerability, line, declaration_text, declaration_line, colored, occurrence, plain):
    # Display detected vulnerability information.
    header = "{}Potential vulnerability found : {}{}{}".format('' if plain else '\033[1m', '' if plain else '\033[92m', payload[1], '' if plain else '\033[0m')

    #Display the line and file path where the vulnerability was found.
    line = "-->{}{}{} in {}".format('' if plain else '\033[92m', line, '' if plain else '\033[0m', path)

    # Highlight the vulnerable code snippet.
    vuln = nth_replace("".join(vulnerability), colored, "{}".format('' if plain else '\033[92m') + colored + "{}".format('' if plain else '\033[0m'), occurrence)
    vuln = "{}({})".format(payload[0], vuln)

    # Print the vulnerability information.
    # rows, columns = os.popen('stty size', 'r').read().split()
    rows = 45
    columns = 190
    print("-" * (int(columns) - 1))
    print("Name        \t{}".format(header))
    print("-" * (int(columns) - 1))
    print("{}Line {}             {}".format('' if plain else '\033[1m', '' if plain else '\033[0m', line))
    print("{}Code {}             {}".format('' if plain else '\033[1m', '' if plain else '\033[0m', vuln))

    # Display information about the declaration of the vulnerable variable, if available.
    if "$_" not in colored:
        declared = "Undeclared in the file"
        if declaration_text != "":
            declared = "Line n°{}{}{} : {}".format('' if plain else '\033[0;92m', declaration_line, '' if plain else '\033[0m', declaration_text)
        print("{}Declaration {}      {}".format('' if plain else '\033[1m', '' if plain else '\033[0m', declared))
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
