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