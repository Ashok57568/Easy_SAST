from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os

def wrap_text(pdf_canvas, text, max_width):
    # Wrap text to fit within the specified max_width
    lines = []
    current_line = ""
    
    for word in text.split():
        if pdf_canvas.stringWidth(current_line + word, 'Helvetica', 12) < max_width:
            current_line += word + " "
        else:
            lines.append(current_line.strip())
            current_line = word + " "
    
    lines.append(current_line.strip())
    
    return lines

def create_pdf_report(input_file, output_file):

    # Create a PDF document
    pdf_canvas = canvas.Canvas(output_file, pagesize=letter)
    
    # Set font and size for the title
    pdf_canvas.setFont("Helvetica-Bold", 16)
    
    # Add the big heading
    # Coordinates for the title
    title_x = pdf_canvas._pagesize[0] / 2  # Center of the page
    title_y = pdf_canvas._pagesize[1] - 50

    # Set font and size for the title
    pdf_canvas.setFont("Helvetica-Bold", 16)
