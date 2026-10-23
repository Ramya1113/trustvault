#!/usr/bin/env bash
# Exit immediately if a command exits with a non-zero status
set -o errexit

export FLASK_APP=run.py

echo "==> Installing Python dependencies..."
pip install -r requirements.txt

echo "==> Initializing database tables..."
flask --app run.py init-db

if [ "${SEED_DEMO}" = "1" ]; then
    echo "==> SEED_DEMO=1 detected. Seeding demo organization and accounts..."
    flask --app run.py seed
fi

echo "==> Build completed successfully!"
