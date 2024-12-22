import argparse
import os

def setup_parser():
    """
    Set up argument parser for user input.
    """
    parser = argparse.ArgumentParser(description="Code vulnerability scanner (EasySAST)")
    parser.add_argument("path", help="Path to directory or file to scan")
    parser.add_argument("--output", choices=["plain", "colored", "json", "pdf"], default="plain", help="Specify output format")
    return parser

def scan_directory(path, output_format):
    """
    Recursively scan directory for vulnerabilities.
    """
    if not os.path.exists(path):
        print(f"Error: The specified path '{path}' does not exist.")
        return

    if os.path.isfile(path):
        
        scan_file(path, output_format)
    elif os.path.isdir(path):
        
        for root, _, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                scan_file(file_path, output_format)

def scan_file(file_path, output_format):
    """
    Scan individual file for vulnerabilities.
    """
    print(f"Scanning {file_path}...")


    with open(file_path, 'r', encoding="utf-8", errors="ignore") as file:
        code = file.read()

    
    clean_code = clean_source_and_format(code)

    
    vulnerabilities = detect_vulnerabilities(clean_code)

    
    output_results(vulnerabilities, output_format)

def clean_source_and_format(code):
    """
    Temporary placeholder function for cleaning and formatting the code.
    """

    return code

def detect_vulnerabilities(clean_code):
    """
    Temporary placeholder function for detecting vulnerabilities.
    """
    
    return [
        {
            "file": "example.php",
            "line": 12,
            "vulnerability": "SQL Injection",
            "description": "Possible SQL injection vulnerability."
        }
    ]

def output_results(vulnerabilities, output_format):
    """
    Output the results of the scan based on the specified format.
    """
    if output_format == "plain":
        print(vulnerabilities)
    elif output_format == "colored":
       
        print(f"\033[91m{vulnerabilities}\033[0m")
    elif output_format == "json":
        import json
        print(json.dumps(vulnerabilities, indent=4))
    elif output_format == "pdf":
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas

        pdf_path = "scan_report.pdf"
        c = canvas.Canvas(pdf_path, pagesize=letter)
        c.drawString(100, 750, "Scan Results:")
        c.drawString(100, 735, str(vulnerabilities))
        c.save()

        print(f"Report saved as {pdf_path}")

def main():
    """
    Main entry point for EasySAST script.
    """
    parser = setup_parser()
    args = parser.parse_args()

   
    scan_directory(args.path, args.output)

if __name__ == "__main__":
    main()
