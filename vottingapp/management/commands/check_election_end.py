from django.core.management.base import BaseCommand
from django.utils import timezone
from vottingapp.models import ElectionSettings, AuditLog, CustomUser
from django.conf import settings
from django.core.mail import send_mass_mail
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Check if election should end based on scheduled time'
    
    def handle(self, *args, **options):
        try:
            # Get election settings
            try:
                election_settings = ElectionSettings.objects.get(id=1)
            except ElectionSettings.DoesNotExist:
                self.stdout.write(self.style.WARNING('No election settings found'))
                return
            
            # Only check if election is active
            if not election_settings.is_active:
                self.stdout.write(self.style.WARNING('Election is not active'))
                return
            
            # Get current time
            now = timezone.now()
            
            # Convert end_date to timezone-aware datetime if it's naive
            end_date = election_settings.end_date
            if timezone.is_naive(end_date):
                end_date = timezone.make_aware(end_date)
            
            # Check if end time has passed
            if end_date <= now:
                # End the election
                election_settings.is_active = False
                election_settings.save()
                
                # Send election end emails
                self.send_election_ended_emails(election_settings)
                
                # Create audit log
                AuditLog.objects.create(
                    user=None,  # System action
                    action='election_ended',
                    details="Election ended automatically"
                )
                
                self.stdout.write(
                    self.style.SUCCESS('Election ended automatically and emails sent')
                )
            else:
                # Calculate time until election ends
                time_until_end = end_date - now
                days = time_until_end.days
                hours, remainder = divmod(time_until_end.seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                
                self.stdout.write(
                    self.style.SUCCESS(f'Election active. Time remaining: {days}d {hours}h {minutes}m')
                )
                
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error checking election end: {str(e)}')
            )
    
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