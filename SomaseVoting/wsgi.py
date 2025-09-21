"""
WSGI config for SomaseVoting project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/howto/deployment/wsgi/

import os

from django.core.wsgi import get_wsgi_application

#os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'SomaseVoting.settings')

settings_module='SomaseVoting.deployment_settings' if 'RENDER_EXTERNAL_HOSTNAME' in os.environ else 'SomaseVoting.settings'
os.environ.setdefault('DJANGO_SETTINGS_MODULE', settings_module)
application = get_wsgi_application()"""
"""
WSGI config for SomaseVoting project.
"""

import os
from django.core.wsgi import get_wsgi_application

settings_module = 'SomaseVoting.deployment_settings' if 'RENDER_EXTERNAL_HOSTNAME' in os.environ else 'SomaseVoting.settings'
os.environ.setdefault('DJANGO_SETTINGS_MODULE', settings_module)

# Import and start scheduler after application is loaded
application = get_wsgi_application()

# Start scheduler after application is loaded
try:
    from vottingapp.scheduler import start_scheduler
    start_scheduler()
except Exception as e:
    import logging
    logger = logging.getLogger(__name__)
    logger.error(f"Failed to start scheduler: {str(e)}")
