#!/usr/bin/env bash
# Exit on error
set -o errexit

# Install dependencies
pip install -r requirements.txt

# Apply core migrations first (including auth)
python manage.py migrate auth --noinput
python manage.py migrate contenttypes --noinput

# Then migrate the custom user app
python manage.py migrate vottingapp --noinput

# Finally run all other migrations
python manage.py migrate --noinput

# Collect static files
python manage.py collectstatic --noinput

if [[$CREATE_SUPERUSER]]:
   then
     python manage.py createsuperuser --noinput
fi
