// DOM Elements
const fileInput = document.getElementById('fileInput');
const fileName = document.getElementById('fileName');
const analyzeBtn = document.getElementById('analyzeBtn');
const dropArea = document.getElementById('dropArea');
const resultsBox = document.getElementById('resultsBox');
const loadingSpinner = document.getElementById('loadingSpinner');
const resultsSection = document.getElementById('resultsSection');
const downloadBtn = document.getElementById('downloadBtn');
const toast = document.getElementById('toast');

// Event Listeners for file upload
fileInput.addEventListener('change', handleFileSelect);
dropArea.addEventListener('dragover', handleDragOver);
dropArea.addEventListener('dragleave', handleDragLeave);
dropArea.addEventListener('drop', handleDrop);
analyzeBtn.addEventListener('click', analyzeFile);
downloadBtn.addEventListener('click', downloadPDF);

// File handling functions
function handleFileSelect(e) {
  const file = e.target.files[0];
  if (file) {
    validateAndDisplayFile(file);
  }
}

function handleDragOver(e) {
  e.preventDefault();
  e.stopPropagation();
  dropArea.classList.add('active');
}

function handleDragLeave(e) {
  e.preventDefault();
  e.stopPropagation();
  dropArea.classList.remove('active');
}

function handleDrop(e) {
  e.preventDefault();
  e.stopPropagation();
  dropArea.classList.remove('active');
  
  const file = e.dataTransfer.files[0];
  if (file) {
    fileInput.files = e.dataTransfer.files;
    validateAndDisplayFile(file);
  }
}

function validateAndDisplayFile(file) {
  // Check if file is PHP
  if (file.name.toLowerCase().endsWith('.php')) {
    fileName.textContent = file.name;
    fileName.style.display = 'block';
    analyzeBtn.disabled = false;
  } else {
    showToast('Please upload a PHP file (.php extension)', 'error');
    resetFileInput();
  }
}

function resetFileInput() {
  fileInput.value = '';
  fileName.textContent = '';
  fileName.style.display = 'none';
  analyzeBtn.disabled = true;
}

function analyzeFile() {
  const file = fileInput.files[0];
  if (!file) {
    showToast('Please select a PHP file first', 'error');
    return;
  }

  // Show loading state
  loadingSpinner.style.display = 'block';
  resultsSection.style.display = 'none';
  analyzeBtn.disabled = true;

  const formData = new FormData();
  formData.append('file', file);

  // Make API request
  fetch('http://localhost:5000/upload', {
    method: 'POST',
    body: formData
  })
  .then(response => {
    if (!response.ok) {
      throw new Error('Server error: ' + response.status);
    }
    return response.json();
  })
  .then(data => {
    // Hide loading spinner
    loadingSpinner.style.display = 'none';
    resultsSection.style.display = 'block';
    
    // Store the PDF URL for later download
    window.pdfUrl = data.pdfUrl;
    
    // Display the download button
    downloadBtn.style.display = 'inline-block';
    
    // Display success message
    resultsBox.innerHTML = `
      <div class="vulnerability severity-high">
        <h3>Analysis Complete</h3>
        <p>Your PHP file has been analyzed successfully. The report is ready for download.</p>
      </div>
      <div class="vulnerability severity-medium">
        <h3>What's Next?</h3>
        <p>Click the "Download PDF Report" button above to view the detailed analysis of vulnerabilities found in your code.</p>
      </div>
      <div class="vulnerability-code">
        File analyzed: ${file.name}<br>
        Size: ${(file.size / 1024).toFixed(2)} KB<br>
        Timestamp: ${new Date().toLocaleString()}<br>
        Report URL: <a href="${data.pdfUrl}" target="_blank">${data.pdfUrl}</a>
      </div>
    `;
    
    showToast('Analysis completed successfully', 'success');
  })
  .catch(error => {
    console.error('Error:', error);
    loadingSpinner.style.display = 'none';
    resultsSection.style.display = 'block';
    resultsBox.innerHTML = `
      <div class="vulnerability severity-high">
        <h3>Error</h3>
        <p>An error occurred during analysis: ${error.message}</p>
        <p>Please try again or check if the server is running.</p>
      </div>
    `;
    showToast('Error analyzing file', 'error');
  })
  .finally(() => {
    analyzeBtn.disabled = false;
  });
}

// Download PDF function
function downloadPDF() {
  if (!window.pdfUrl) {
    showToast('No report available for download', 'error');
    return;
  }
  
  // Open PDF in new tab
  window.open(window.pdfUrl, '_blank');
}

// Toast notification function
function showToast(message, type = 'default') {
  toast.textContent = message;
  toast.className = 'toast ' + type;
  toast.classList.add('show');
  
  setTimeout(() => {
    toast.classList.remove('show');
  }, 3000);
}