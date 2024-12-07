#!/bin/bash

# Check if Python virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install requirements if they exist
if [ -f "requirements.txt" ]; then
    echo "Installing requirements..."
    pip install -r requirements.txt
fi

# Run Flask application
echo "Starting Flask application..."
export FLASK_APP=app.py
export FLASK_ENV=development
flask run &

# Setup telebit forwarding
echo "Setting up telebit forwarding..."
export XDG_RUNTIME_DIR=/run/user/$UID
systemctl --user restart telebit
sleep 3
# Forward port 5000
~/telebit http 5000