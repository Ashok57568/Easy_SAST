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
return new.join(nth_split)
    return string.replace(old, new)


def display(path, payload, vulnerability, line, declaration_text, declaration_line, colored, occurrence, plain):
    # Display detected vulnerability information.
    header = "{}Potential vulnerability found : {}{}{}".format('' if plain else '\033[1m', '' if plain else '\033[92m', payload[1], '' if plain else '\033[0m')

    #Display the line and file path where the vulnerability was found.
    line = "-->{}{}{} in {}".format('' if plain else '\033[92m', line, '' if plain else '\033[0m', path)

