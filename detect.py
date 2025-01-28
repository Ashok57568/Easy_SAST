import os
import re
import math
from indicators import *
from feature import *

result_count = 0
result_files = 0

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
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy


def analysis(path, plain):
    """
    Analyzes a single file's source code to identify security vulnerabilities such as hardcoded credentials
    and strings with high entropy, which could indicate sensitive data.
    
    Parameters:
    - path: Path to the file to analyze.
    - plain: Boolean flag indicating whether output should be formatted as plain text.
    """

    global result_count
    global result_files
    result_files += 1
    with open(path, 'r', encoding='utf-8', errors='replace') as content_file:

        # Clean source for a better detection
        content = content_file.read()
        content = clean_source_and_format(content)

        # Hardcoded credentials (work as an exception, it's not function based)
        credz = ['pass', 'secret', 'token', 'pwd', 'api-key']
        for credential in credz:
            content_pure = content.replace(' ', '')

            # detect all variables
            regex_var_detect = "\$[\w\s]+\s?=\s?[\"|'].*[\"|']|define\([\"|'].*[\"|']\)"
            regex = re.compile(regex_var_detect , re.I)
            matches = regex.findall(content_pure)
            
            # If we find a variable with a constant for a given indicator
            for vuln_content in matches:
                if credential in vuln_content.lower():
                    payload = ["", "Hardcoded Credential", []]
                    add_vuln_var(payload, plain, path, vuln_content, content, regex_var_detect)

        
        # High Entropy String
        content_pure = content.replace(' ', '')
        regex_var_detect = ".*?=\s?[\"|'].*?[\"|'].*?"
        regex = re.compile(regex_var_detect , re.I)
        matches = regex.findall(content_pure)
        BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        HEX_CHARS = "1234567890abcdefABCDEF"

        for vuln_content in matches:
            payload = ["", "High Entropy String", []]
            if shannon_entropy(vuln_content, BASE64_CHARS) >= 4.1 or \
                shannon_entropy(vuln_content, HEX_CHARS) >= 2.5:
                add_vuln_var(payload, plain, path, vuln_content, content, regex_var_detect)