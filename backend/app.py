import os
import time
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from subprocess import run

app = Flask(__name__)
CORS(app)  # Allow requests from your React frontend

# Define folders for uploads and outputs
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'outputs'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Save the file
    timestamp = int(time.time())
    filename = f"{timestamp}_{file.filename}"
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)

    # Define the output PDF file path
    output_pdf = os.path.join(OUTPUT_FOLDER, f"{timestamp}_output.pdf")

    # Call your scanning code (adjust this command as needed)
    command = f"python EasySAST.py --input \"{file_path}\" --output \"{output_pdf}\""

    result = run(command, shell=True)

    if result.returncode != 0:
        return jsonify({'error': 'Error processing file'}), 500

    # Return the URL of the generated PDF
    pdf_url = f"http://localhost:5000/outputs/{os.path.basename(output_pdf)}"
    return jsonify({'pdfUrl': pdf_url})

# Serve generated PDF files
@app.route('/outputs/<filename>', methods=['GET'])
def get_output(filename):
    return send_from_directory(OUTPUT_FOLDER, filename, mimetype='application/pdf')


if __name__ == '__main__':
    app.run(port=5000, debug=True)