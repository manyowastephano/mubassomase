# users/management/commands/check_election_status.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from vottingapp.models import ElectionSettings, AuditLog, CustomUser
from django.conf import settings
from django.core.mail import send_mass_mail
from django.db.models import Q
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Check and update election status based on scheduled times'

    def handle(self, *args, **options):
        now = timezone.now()
        
        # Check for elections that should start
        elections_to_start = ElectionSettings.objects.filter(
            start_date__lte=now,
            is_active=False
        )
        
        for election in elections_to_start:
            election.is_active = True
            election.save()
            
            # Send election start emails
            self.send_election_started_emails(election)
            
            # Create audit log
            AuditLog.objects.create(
                user=None,  # System action
                action='election_start',
                details=f"Election started automatically: {election.election_title}"
            )
            
            self.stdout.write(
                self.style.SUCCESS(f'Election "{election.election_title}" started automatically')
            )
        
        # Check for elections that should end
        elections_to_end = ElectionSettings.objects.filter(
            end_date__lte=now,
            is_active=True
        )
        
        for election in elections_to_end:
            election.is_active = False
            election.save()
            
            # Send election end emails
            self.send_election_ended_emails(election)
            
            # Create auditLog
            AuditLog.objects.create(
                user=None,  # System action
                action='election_end',
                details=f"Election ended automatically: {election.election_title}"
            )
            
            self.stdout.write(
                self.style.SUCCESS(f'Election "{election.election_title}" ended automatically')
            )
        
        # If no changes were made
        if not elections_to_start and not elections_to_end:
            self.stdout.write(
                self.style.SUCCESS('No election status changes needed at this time')
            )
    
    def send_election_started_emails(self, election_settings):
        """Send election started notification emails to all users"""
        # Get all user emails
        user_emails = CustomUser.objects.filter(is_active=True).values_list('email', flat=True)
        user_emails = [email for email in user_emails if email]
        
        if not user_emails:
            logger.warning("No users found to send election start emails")
            return
        
        # Get additional emails from election settings
        additional_emails = election_settings.get_additional_emails_list()
        
        # Combine all emails
        all_emails = list(user_emails) + additional_emails
        
        # Email content
        subject = f'MUBAS SOMASE Elections Has Started'
        
        message = f"""
Hello everyone,

The MUBAS SOMASE ELECTIONS has now started.

Please log in to the system to cast your vote: http://localhost:3000/login

The election will end on {election_settings.end_date.strftime("%Y-%m-%d at %H:%M")}.

Thank you for participating in the democratic process.

Best regards,
MUBAS SOMASE Election Committee
"""
        
        # Prepare emails for mass sending
        emails = [(subject, message, settings.DEFAULT_FROM_EMAIL, [email]) for email in all_emails]
        
        # Send emails
        send_mass_mail(emails, fail_silently=False)
        
        logger.info(f"Sent election start emails to {len(all_emails)} recipients")
    
    def send_election_ended_emails(self, election_settings):
        """Send election ended notification emails to all users"""
        # Get all user emails
        user_emails = CustomUser.objects.filter(is_active=True).values_list('email', flat=True)
        user_emails = [email for email in user_emails if email]
        
        if not user_emails:
            logger.warning("No users found to send election end emails")
            return
        
        # Get additional emails from election settings
        additional_emails = election_settings.get_additional_emails_list()
        
        # Combine all emails
        all_emails = list(user_emails) + additional_emails
        
        # Email content
        subject = f'MUBAS SOMASE Elections Has Ended'
        
        message = f"""
Hello everyone,

The MUBAS SOMASE ELECTIONS has officially ended.

Thank you to everyone who participated in the voting process. The results will be announced soon.

If you haven't voted yet, you can no longer do so as the election period has ended.

Best regards,
MUBAS SOMASE Election Committee
"""
        
        # Prepare emails for mass sending
        emails = [(subject, message, settings.DEFAULT_FROM_EMAIL, [email]) for email in all_emails]
        
        # Send emails
        send_mass_mail(emails, fail_silently=False)
        
        logger.info(f"Sent election end emails to {len(all_emails)} recipients")