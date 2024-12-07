#!/bin/bash

echo "Stopping Flask server..."
# Find and kill Flask process
FLASK_PID=$(ps aux | grep "flask run" | grep -v grep | awk '{print $2}')
if [ -n "$FLASK_PID" ]; then
    kill $FLASK_PID
    echo "Flask server stopped (PID: $FLASK_PID)"
else
    echo "No Flask server process found"
fi

# Wait a moment to ensure port is freed
sleep 2

echo "Starting Flask server..."
# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Export Flask environment variables
export FLASK_APP=app.py
export FLASK_ENV=development

# Start Flask in background
flask run &

# Wait for Flask to start
sleep 3

echo "Restarting telebit..."
# Setup telebit forwarding
export XDG_RUNTIME_DIR=/run/user/$UID
systemctl --user restart telebit
sleep 3
# Forward port 5000
~/telebit http 5000

echo "Restart complete!"
