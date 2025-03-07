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