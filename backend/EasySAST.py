#!/usr/bin/python
# -*- coding: utf-8 -*-

import time
import sys
import argparse
import os
from detect import analysis, recursive, scanresults
from pdfgen import create_pdf_report

if __name__ == "__main__":
    # Set up argument parsing
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True, help="Provide file or directory to analyse")
    parser.add_argument('--output', required=True, help="Provide output PDF file path")
    parser.add_argument('--plain', action='store_true', help="Plain output (without color)")
    args = parser.parse_args()

    # Display the banner/UI
    print("""
    
 _______  _______  _______  __   __  _______  _______  _______  _______ 
|       ||   _   ||       ||  | |  ||       ||   _   ||       ||       |
|    ___||  |_|  ||  _____||  |_|  ||  _____||  |_|  ||  _____||_     _|
|   |___ |       || |_____ |       || |_____ |       || |_____   |   |  
|    ___||       ||_____  ||_     _||_____  ||       ||_____  |  |   |  
|   |___ |   _   | _____| |  |   |   _____| ||   _   | _____| |  |   |  
|_______||__| |__||_______|  |___|  |_______||__| |__||_______|  |___|  

        Made By: Ashok Dhungana |  
    """)
    
    print("\n{}Analyzing '{}' source code{}".format(
        '' if args.plain else '\033[1m',
        args.input,
        '' if args.plain else '\033[0m'
    ))
    time.sleep(5)

    # Perform vulnerability analysis
    if os.path.isfile(args.input):
        analysis(args.input, args.plain)
    else:
        recursive(args.input, 0, args.plain)
    
    # Display the scan results summary
    scanresults()

    # Define the report folder (where scanresults writes the vulnerability report text files)
    report_folder = "Report"

    # Check if the report folder exists before generating PDF
    if not os.path.exists(report_folder):
        print("No report folder found. No vulnerability report generated.")
    else:
        # Generate the PDF report using pdfgen module
        create_pdf_report(report_folder, args.output)
        print(f"PDF report generated successfully at: {args.output}")