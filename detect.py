#!/usr/bin/python
# -*- coding: utf-8 -*-
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