# vottingapp/scheduler.py
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from django_apscheduler.jobstores import DjangoJobStore
from django_apscheduler.models import DjangoJobExecution
from django_apscheduler import util
from django.conf import settings
from django.core.management import call_command
import logging
import os

logger = logging.getLogger(__name__)

def start_scheduler():
    # Don't run in development or if on Render free tier (no reliable background processes)
    if settings.DEBUG or os.environ.get('RENDER_EXTERNAL_HOSTNAME'):
        logger.info("Scheduler running in limited mode due to environment constraints")
        # We'll still run but with awareness of limitations
        pass
    
    scheduler = BackgroundScheduler()
    scheduler.add_jobstore(DjangoJobStore(), "default")
    
    # Schedule election check every 5 minutes
    scheduler.add_job(
        check_election_status,
        trigger=IntervalTrigger(minutes=5),
        id="election_check",
        max_instances=1,
        replace_existing=True,
    )
    
    try:
        logger.info("Starting scheduler...")
        scheduler.start()
    except Exception as e:
        logger.error(f"Failed to start scheduler: {str(e)}")

def check_election_status():
    """Check if election should start or end"""
    try:
        from django.core.management import call_command
        call_command('check_election_end')
    except Exception as e:
        logger.error(f"Error checking election status: {str(e)}")

# Optional: Clean up old job executions
@util.close_old_connections
def delete_old_job_executions(max_age=604_800):
    DjangoJobExecution.objects.delete_old_job_executions(max_age)