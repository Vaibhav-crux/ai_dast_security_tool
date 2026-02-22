# AutoVAPT Setup Script
Write-Host "Setting up AutoVAPT..." -ForegroundColor Green

# Create virtual environment
Write-Host "Creating virtual environment..." -ForegroundColor Yellow
python -m venv venv
./venv/Scripts/Activate

# Install requirements
Write-Host "Installing requirements..." -ForegroundColor Yellow
python -m pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
Write-Host "Creating directories..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path scan_results
New-Item -ItemType Directory -Force -Path reports
New-Item -ItemType Directory -Force -Path logs
New-Item -ItemType Directory -Force -Path "models/cache"
New-Item -ItemType Directory -Force -Path "assets/icons"

# Create .env file if it doesn't exist
if (-not(Test-Path -Path ".env")) {
    Write-Host "Creating .env file..." -ForegroundColor Yellow
    Copy-Item "sample.env" ".env"
    Write-Host "Please update the .env file with your settings" -ForegroundColor Red
}

# Check ZAP installation
$zapPath = "C:\Program Files\ZAP"
if (-not(Test-Path -Path $zapPath)) {
    Write-Host "OWASP ZAP not found at default location." -ForegroundColor Red
    Write-Host "Please install OWASP ZAP and update the ZAP_PATH in .env file" -ForegroundColor Red
}

# Check AI model
$modelPath = "models/q4_0-orca-mini-3b.gguf"
if (-not(Test-Path -Path $modelPath)) {
    Write-Host "AI model not found!" -ForegroundColor Red
    Write-Host "Please download Q4_0-Orca-Mini-3B model and place it in the models directory" -ForegroundColor Red
}

Write-Host "`nSetup completed!" -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "1. Update the .env file with your settings" -ForegroundColor White
Write-Host "2. Ensure OWASP ZAP is installed" -ForegroundColor White
Write-Host "3. Download and place the AI model in the models directory" -ForegroundColor White
Write-Host "4. Run 'python main.py' to start AutoVAPT" -ForegroundColor White 