#!/bin/bash

# Source shared utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "$SCRIPT_DIR/utils.sh"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    log_message "INFO" "Creating virtual environment..."
    python -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
log_message "INFO" "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
log_message "INFO" "Installing dependencies..."
pip install -r requirements.txt

# Install development dependencies if requested
if [ "$1" == "--dev" ]; then
    log_message "INFO" "Installing development dependencies..."
    pip install -r requirements-dev.txt
fi

# Create necessary directories
ensure_directories "instance" "logs" "flask_session"

log_message "INFO" "Setup complete! Activate the virtual environment with:"
echo "source venv/bin/activate"
echo ""
log_message "INFO" "Start the application with:"
echo "python run.py" 