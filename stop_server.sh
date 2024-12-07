#!/bin/bash

# Find the Flask process
FLASK_PID=$(ps aux | grep "flask run" | grep -v grep | awk '{print $2}')

if [ -n "$FLASK_PID" ]; then
    echo "Stopping Flask server (PID: $FLASK_PID)..."
    kill $FLASK_PID
    echo "Flask server stopped"
else
    echo "No Flask server process found"
fi
