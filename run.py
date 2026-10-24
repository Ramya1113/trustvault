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
    # In development, run on localhost; debug is enabled only if FLASK_DEBUG=1
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(host='127.0.0.1', port=port, debug=debug_mode)

