"""
Development entry point for TrustVault.

Run this script to start the local Flask development server:
    python run.py
"""
import os
from app import create_app

# Instantiate the Flask application via factory
app = create_app()

if __name__ == '__main__':
    # Retrieve port from environment if set, otherwise default to 5000
    port = int(os.environ.get('PORT', 5000))
    # In development, run on localhost with debugging enabled
    app.run(host='127.0.0.1', port=port, debug=True)
